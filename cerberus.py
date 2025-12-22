from flask import Flask, jsonify, request
from functools import wraps
from jwt import InvalidTokenError, ExpiredSignatureError

import echidna

app = Flask(__name__)
app.config['SECRET_KEY'] = echidna.send_secret()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or request.form
    try:
        user = echidna.User(**data)
        user.check_before_entry()
        echidna.isNameAvailable(user.name)
        echidna.checkUserExists(user, False)
        user.confirm_password(data.get('confirm_password', ''))
        echidna.registerUser(user) # user is unverified at this point
        echidna.attempt_verification(user,channel=data.get('channel',''),purpose='registration')
        return jsonify({'message': 'Registration Successful'}), 201
    except ValueError as ve:
        return jsonify({'message': str(ve)}), 401
    except ConnectionError as ce:
        return jsonify({'message': str(ce)}), 500
    except Exception:
        return jsonify({'message': 'Something went wrong!'}), 401

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True) or request.form
        user = echidna.User(**data)
        echidna.checkUserExists(user, True, True)
        password = echidna.getUserPasswordHash(user)
        echidna.verify_password(user.password, password)
        response = jsonify({'message': 'Login Successful'})

        prodigy_id = str(echidna.get_prodigy_id(user))
        token = echidna.make_access_token(prodigy_id, ttl_minutes=30)
        print(f"Generated token for prodigy_id {prodigy_id}: {token}...")
        response.set_cookie(
            'jwt', token,
            httponly=True, secure=request.is_secure, samesite='Lax', path='/',
            max_age=30*60
        )
        return response, 200
    except ValueError as ve:
        return jsonify({'message': str(ve)}), 401
    except ConnectionError as ce:
        return jsonify({'message': str(ce)}), 500
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'message': 'Something went wrong'}), 401

@app.route('/verify', methods=["POST"])
def verify_or_forgot():
    try:
        data = request.get_json(silent=True) or request.form
        user = echidna.User(**data) 
        channel_choice = data.get('channel', 'email' if user.email else 'telegram')
        code = data.get('code', '')
        purpose = data.get('purpose', 'reset')

        if not code:
            echidna.attempt_verification(user, channel_choice, purpose='reset')
            return jsonify({'message': 'OTP sent successfully'}), 200
        else:
            echidna.verify_otp(user, code, purpose=purpose, channel=channel_choice)
            if purpose == 'reset':
               user.confirm_password(data.get('confirm_password', ''))
               echidna.update_password(user)
               return jsonify({'message': 'Password reset successful'}), 200
            elif purpose == 'registration':
               echidna.mark_user_verified(user)
               return jsonify({'message': 'Successful Verification'}), 200
            else:
                return jsonify({'message': 'Done!'}), 200

    except ValueError as ve:
        return jsonify({'message': str(ve)}), 401
    except ConnectionError as ce:
        return jsonify({'message': str(ce)}), 500
    except Exception as e:
        print(f"Error in forgot_password: {e}")
        return jsonify({'message': 'Something went wrong!'}), 401


def token_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        bearer = request.headers.get("Authorization", "")
        token = request.cookies.get('jwt') or (bearer.split(" ",1)[1] if bearer.lower().startswith("bearer ") else None)
        if not token:
            return jsonify({"message": "Missing token"}), 401
        try:
            claims = echidna.decode_access_token(token)
            sub = claims["sub"]
            echidna.assert_prodigy_exists(sub)

            # 1) JTI revocation
            jti = claims.get("jti")
            if jti and echidna.is_access_jti_revoked(jti):
                return jsonify({"message": "Token revoked"}), 401

            # 2) Version + password-change cutoff with skew
            ver_claim = int(claims.get("ver", -1))
            ver_db, pw_cutoff, iat = echidna.get_user_token_guard(sub, int(claims["iat"]))

            if ver_claim != ver_db:
                return jsonify({"message": "Token superseded"}), 401

            skew = 10
            if iat < (pw_cutoff - echidna.timedelta(seconds=skew)):
                print(f"[debug] iat={iat.isoformat()} pw_cutoff={pw_cutoff.isoformat()} skew={skew}s")
                return jsonify({"message": "Token older than password change"}), 401

        except ExpiredSignatureError:
            return jsonify({"message": "Token expired", "redirect": "/login"}), 401
        except InvalidTokenError:
            return jsonify({"message": "Invalid token", "redirect": "/login"}), 401
        except Exception as e:
            print(f"Error in token verification: {e}")
            return jsonify({"message": "Token verification failed", "redirect": "/login"}), 401
        return f(sub, *args, **kwargs)
    return wrapped

def extract_token_from_request() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    cookie_token = request.cookies.get("jwt")
    if cookie_token:
        return cookie_token
    raise ValueError("No token provided")


@app.route('/dashboard')
@token_required
def dashboard(pid: str):
    return jsonify({'message': f"Welcome {pid}! You are logged in."})

@app.post("/logout")
@token_required
def logout(pid: str):
    # revoke the current access token JTI
    try:
        token = extract_token_from_request()
        claims = echidna.decode_access_token(token)
        jti = claims.get("jti")
        exp = claims.get("exp") or 0
        echidna.revoke_access_jti(jti, int(pid), exp)
    except Exception as e:
        print(f"Error in logout token revocation: {e}")

    want_all = False
    if request.is_json:
        want_all = bool((request.get_json(silent=True) or {}).get("all"))
    else:
        want_all = request.args.get("all", "").lower() in ("1", "true", "yes")

    if want_all:
        try:
            echidna.delete_refresh_tokens(int(pid))
        except Exception:
            pass

    resp = jsonify({"message": "Logged out"})
    resp.delete_cookie("jwt", path="/", samesite="Lax", secure=request.is_secure)
    return resp, 200

@app.post("/admin/rotate-keys")
def rotate_keys():
    """
    Rotates JWT signing keys.
    Body (JSON, all optional):
      bits: int (default 2048)
      grace_minutes: int (default 45)  grace window for accepting the retired key
      kid: string (default uuid4)      supply to control filename and kid
    """
    try:
        CERBERUS_SECRET = echidna.send_secret()
        token = request.args.get("token", "")
        if not token: return "forbidden", 403
        if token != CERBERUS_SECRET: return f"forbidden", 403
        body = request.get_json(silent=True) or {}
        bits, grace_minutes, new_kid = echidna.resolve_rotate_keys_auth(body)

        # 1) generate keypair in-process (PEM strings), then write to disk
        private_pem, public_pem = echidna.gen_rsa_pair(new_kid, bits=bits)
        echidna.write_key_files(new_kid, private_pem, public_pem)

        # 2) insert public key as 'staging'
        echidna._insert_staging_key(new_kid, public_pem)

        # 3) switch signer to new kid and flip statuses
        resp = echidna._promote_and_retire(new_kid, grace_minutes)
        echidna._write_active_kid(new_kid)
        return jsonify(resp), 200

    except PermissionError as pe:
        print(f"Error in rotate_keys: {pe}")
        return jsonify({"message": "Forbidden"}), 403
    except Exception as e:
        print(f"Error in rotate_keys: {e}")
        return jsonify({"message": "Rotation failed"}), 500


if __name__ == '__main__':
    app.run(port=5000, debug=True)