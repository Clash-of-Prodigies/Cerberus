from flask import Flask, jsonify, request
from functools import wraps
from jwt import InvalidTokenError, ExpiredSignatureError
from urllib.parse import urlparse

import echidna
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

app = Flask(__name__)
app.config['SECRET_KEY'] = echidna.send_secret()

ALLOWED_ROOTS = ["clash-of-prodigies.github.io", "auth.clashofprodigies.org"]

def is_allowed_origin(origin: str) -> bool:
    if not origin:
        return False
    parsed = urlparse(origin)
    host = parsed.hostname
    if not host:
        return False
    return any(host == root for root in ALLOWED_ROOTS)

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and is_allowed_origin(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or request.form
    try:
        user = echidna.User(**data)
        user.check_before_entry()
        echidna.isNameAvailable(user.name)
        echidna.checkUserExists(user, False)
        user.confirm_password(data.get('confirm-password', ''))
        echidna.registerUser(user) # user is unverified at this point
        echidna.attempt_verification(user, channel='email', purpose='registration')
        return jsonify({'message': 'Registration Successful'}), 201
    except ValueError as ve:
        return jsonify({'message': str(ve)}), 401
    except ConnectionError as ce:
        return jsonify({'message': str(ce)}), 500
    except Exception as e:
        logging.error(f"Error in registration: {e}")
        return jsonify({'message': 'Something went wrong!'}), 401

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True) or request.form
        user = echidna.User(**data)
        echidna.checkUserExists(user, True)
        password = echidna.getUserPasswordHash(user)
        echidna.verify_password(user.password, password)
        prodigy_id = str(echidna.get_prodigy_id(user))
        token = echidna.make_access_token(prodigy_id, ttl_minutes=30)
        response = jsonify({'message': 'Login Successful', 'authorization': token})
        response.set_cookie(
            'jwt', token,
            httponly=True, secure=True, samesite='Lax', path='/',
            max_age=30*60, domain=".clashofprodigies.org"
        )
        # set authorization header as well for API clients
        response.headers['Authorization'] = f'Bearer {token}'
        return response, 200
    except ValueError as ve:
        return jsonify({'message': str(ve)}), 401
    except ConnectionError as ce:
        return jsonify({'message': str(ce)}), 500
    except Exception as e:
        logging.error(f"Error in login: {e}")
        return jsonify({'message': 'Something went wrong'}), 401

@app.route('/verify', methods=["POST"])
def verify_or_forgot():
    try:
        data = request.get_json(silent=True) or request.form
        user = echidna.User(**data) 
        code = data.get('code', '')
        purpose = data.get('purpose', 'reset')
        channel = data.get('channel', 'email' if user.email else 'telegram') if purpose == 'reset' else 'email'

        if not code:
            echidna.attempt_verification(user, channel, purpose='reset')
            return jsonify({'message': 'OTP sent successfully'}), 200
        else:
            echidna.verify_otp(user, code, purpose=purpose, channel=channel)
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
        logging.error(f"Error in verify: {e}")
        return jsonify({'message': 'Something went wrong!'}), 401


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            resp = echidna.verify_jwt_token(request)
        except (InvalidTokenError, ExpiredSignatureError) as ite:
            logging.error("Cookies: %s", request.cookies)
            return jsonify({"message": str(ite)}), 401, {"Cache-Control": "no-store"}
        except Exception as e:
            logging.error(f"Error in token_required: {e}")
            return jsonify({"message": "Something went wrong"}), 401, {"Cache-Control": "no-store"}
        return f(*args, token_info=resp, **kwargs)
    return decorated


@app.get("/introspect")
@token_required
def introspect(token_info:dict = {}):
    headers = {
        "X-User-Id":   str(token_info["sub"]),
        "X-Token-Exp": str(token_info.get("exp", "")),
        "X-Token-Jti": str(token_info.get("jti", "")),
        "X-Token-Ver": str(token_info.get("ver", "")),
        "Cache-Control": "no-store",
    }
    return ("", 204, headers)

@app.post("/logout")
@token_required
def logout(pid: str, token_info:dict = {}):
    # revoke the current access token JTI
    try:
        jti = token_info.get("jti", "")
        exp = token_info.get("exp", "0")
        echidna.revoke_access_jti(jti, int(pid), exp)
    except Exception as e:
         logging.error(f"Error in logout: {e}")
         return jsonify({"message": "Logout failed"}), 500

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
def controller_rotate_keys():
    CERBERUS_SECRET = echidna.send_secret()
    token = request.args.get("token", "")
    if not token: return "forbidden", 403
    if token != CERBERUS_SECRET: return "forbidden", 403
    body = request.get_json(silent=True) or {}
    try: return jsonify(echidna.rotate_keys(body)), 200
    except PermissionError:
        return jsonify({"message": "Forbidden"}), 403
    except Exception as e:
        logging.error(f"Error in controller_rotate_keys: {e}")
        return jsonify({"message": "Rotation failed"}), 500


if __name__ == '__main__':
    echidna.rotate_keys()
    app.run(host="0.0.0.0", port=5000, debug=True)