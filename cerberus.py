from flask import Flask, jsonify, request
from functools import wraps
from dotenv import load_dotenv
from jwt import InvalidTokenError, ExpiredSignatureError
load_dotenv()

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
        echidna.checkUserExists(user, True)
        password = echidna.getUserPasswordHash(user)
        echidna.verify_password(user.password, password)
        response = jsonify({'message': 'Login Successful'})

        prodigy_id = str(echidna.get_prodigy_id(user))
        token = echidna.make_access_token(prodigy_id, ttl_minutes=30)
        response.set_cookie(
            'jwt', token,
            httponly=True, secure=True, samesite='Lax', path='/',
            max_age=30*60 # Make sure it matches exp in token_creation
        )
        return response, 200
    except ValueError as ve:
        return jsonify({'message': str(ve)}), 401
    except ConnectionError as ce:
        return jsonify({'message': str(ce)}), 500
    except Exception:
        return jsonify({'message': 'Something went wrong'}), 401

@app.route('/forgot', methods=["POST"])
def forgot_password():
    try:
        data = request.get_json(silent=True) or request.form
        user = echidna.User(**data) 
        channel_choice = data.get('channel', 'email' if user.email else 'telegram')
        code = data.get('code', '')
        purpose = data.get('purpose', 'reset')

        if not code:  # initiate
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
            echidna.assert_prodigy_exists(claims["sub"])
        except ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401
        except ValueError as ve:
            return jsonify({"message": str(ve)}), 401
        except Exception as e:
            print(f"Error in token verification: {e}")
            return jsonify({"message": "Token verification failed"}), 401
        return f(claims['sub'], *args, **kwargs)
    return wrapped

@app.route('/dashboard')
@token_required
def dashboard(pid: str):
    return jsonify({'message': f"Welcome {pid}! You are logged in."})

if __name__ == '__main__':
    app.run(port=5000, debug=True)