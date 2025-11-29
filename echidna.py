import secrets, hashlib, hmac
from datetime import datetime, timezone, timedelta
from psycopg import Connection, connect as pg_connect
from psycopg.errors import OperationalError
from dotenv import load_dotenv
load_dotenv()

import os
import re
import requests
import bcrypt
import uuid
import jwt

class User:
    """
    User class to represent a user in the system
    """
    def __init__(self, **kwargs):
        self.email = kwargs.get('email', '')
        self.telegram = kwargs.get('telegram', '')
        self.password = kwargs.get('password', '')
        self.name = kwargs.get('name', '')

    def check_before_entry(self):
        self.email = self.email_check()
        self.telegram = self.telegram_check()
        self.name = self.name_check()
        self.password_check()

    def email_check(self) -> str:
        email = self.email.lower().strip()
        if not email:
            raise ValueError('Email is required!')
        if not re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email):
            raise ValueError('Email format is invalid!')
        url = environmentals('EMAIL_VERIFIER_API', '')
        if url:
            try:
                r = requests.get(url, params={'email': email}, headers={'accept': 'application/json'}).json()
                if not r.get('status', True):
                    raise ValueError('Email is not valid!')
            except Exception:
                # Fail-open by default. If you want strict mode, gate with an env var.
                pass
        return email
    
    def telegram_check(self) -> str:
        chat_id = self.telegram.strip()
        # Accept numeric IDs, including supergroups/channels like "-1001234567890"
        if chat_id and not re.fullmatch(r'-?(?:100)?\d{5,20}', chat_id):
            raise ValueError('Telegram chat id is not valid!')
        return chat_id

    def password_check(self) -> None:
        """
        Check if the provided password meets complexity requirements
        """
        password = self.password
        if len(password) < 8:
            raise ValueError('Password must be at least 8 characters long!')
        if not re.search(r'[A-Z]', password):
            raise ValueError('Password must contain at least one uppercase letter!')
        if not re.search(r'[a-z]', password):
            raise ValueError('Password must contain at least one lowercase letter!')
        if not re.search(r'[0-9]', password):
            raise ValueError('Password must contain at least one digit!')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError('Password must contain at least one special character!')

    def confirm_password(self, confirm_password: str) -> None:
        """
        Confirm that the provided password matches the user's password
        """
        self.password_check()
        if self.password != confirm_password:
            raise ValueError('Passwords do not match!')

    def name_check(self) -> str:
        n = self.name.strip()
        # 5–30 chars, letters/numbers/space and a small safe punctuation set.
        if not re.fullmatch(r"[A-Za-z0-9 _.\-'&!?,@]{5,30}", n):
            raise ValueError('Name must be 5–30 chars of letters, numbers, spaces, and limited punctuation.')
        return n
    
    def clear(self) -> None:
        """
        Clear all information stored in the user instance
        """
        self.email = ''
        self.password = ''
        self.name = ''

def isNameAvailable(name: str, expected: bool = True):
    """
    Check if a username is available in the database
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials WHERE username = %s", (name,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        available = result is None
        if available != expected:
            if expected:
                raise ValueError("Name is already taken.")
            else:
                raise ValueError("Name is available.")
    except Exception as e:
        print(f"Error checking name availability: {e}")
        raise RuntimeError("Failed to check name availability.")

def checkUserExists(user: User, expected: bool):
    try:
        conn = get_connection(); cur = conn.cursor()
        # Look up once, then decide based on status
        cur.execute("""
            SELECT status
              FROM credentials
             WHERE ((email=%s AND %s <> '') OR (telegram=%s AND %s <> ''))
             LIMIT 1
        """, (user.email, user.email, user.telegram, user.telegram))
        row = cur.fetchone()
        cur.close(); conn.close()

        exists = row is not None
        is_active = (row and row[0] == 'active')

        if expected:           # login/reset: must exist AND be active
            if not (exists and is_active):
                raise ValueError("User or password is invalid.")
        else:                  # registration: must NOT exist at all
            if exists:
                raise ValueError("User already exists.")
    except Exception as e:
        print(f"Error checking user existence: {e}")
        raise RuntimeError("Failed to check user existence.")


def getUserPasswordHash(user: User) -> str:
    """
    Retrieve the hashed password for a user from the database
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM credentials WHERE email = %s OR telegram = %s",
                       (user.email, user.telegram))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return result[0]
        else:
            raise ValueError("User or password is invalid.")
    except Exception as e:
        print(f"Error retrieving user password hash: {e}")
        raise RuntimeError("Failed to retrieve user password")

def registerUser(user: User):
    """
    Register a new user in the database
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        hashed_password = hash_password(user.password)
        cursor.execute(
            "INSERT INTO credentials (username, email, telegram, password) VALUES (%s, %s, %s, %s)",
            (user.name, user.email, user.telegram, hashed_password)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error registering user: {e}")
        raise RuntimeError("Failed to register user.")

def environmentals(param: str, default: str = "", delimiter: str = ",") -> str:
    """
    Fetch environment variables, supporting multiple variables separated by a delimiter.

    Args:
        param (str): The environment variable name(s), separated by the delimiter if multiple.
        default (str): The default value(s) to use if the environment variable is not set.
                       If multiple, use the same delimiter as for `param`.
        delimiter (str): The delimiter used to separate multiple variable names and defaults.

    Returns:
        str: The value(s) of the environment variable(s) or the default(s),
             joined by the delimiter if multiple.
    """

    params = [p.strip() for p in param.split(delimiter)]
    defaults = [d.strip() for d in default.split(delimiter)] if default is not None else []

    if len(defaults) < len(params):
        defaults.extend([""] * (len(params) - len(defaults)))

    values = []
    for name, d in zip(params, defaults):
        env_value = os.getenv(name, d)
        values.append(env_value)

    return delimiter.join(values)

def get_connection() -> Connection:
    parts = environmentals("DB_HOST,DB_PORT,DB_NAME,DB_USER,DB_PASSWORD").split(",")
    if len(parts) != 5 or any(not p for p in parts):
        raise ConnectionError("Database configuration is incomplete.")
    db_host, db_port, db_name, db_user, db_password = parts

    try:
        conn = pg_connect(
        host=db_host,
        port=int(db_port),
        dbname=db_name,
        user=db_user,
        password=db_password,
        )
    except OperationalError as e:
        raise ConnectionError(f"Failed to connect to the database: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise ConnectionError(f"An unexpected error occurred")
    return conn

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str):
    if not bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8')):
        raise ValueError("User or password is invalid!")
    
def make_access_token(public_id: str, ttl_minutes=60):
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    ISS = environmentals('JWT_ISS', 'Cerberus')
    AUD = environmentals('JWT_AUD', 'Prodigy')
    SECRET = environmentals('SECRET', '')
    payload = {
            "sub": public_id,
            "iss": ISS,
            "aud": AUD,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
            "jti": jti,
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def send_otp(user: User, code: str, idempotent_key: str, channel: str) -> None:
    """
    Send a verification code to the user's email via the Messenger service
    """
    if not channel:
        if user.email:
            channel = 'email'
        elif user.telegram:
            channel = 'telegram'
        else:
            raise ValueError("No contact information provided for verification.")
    recipient = user.email if channel == 'email' else user.telegram
    MESSENGER_SERVICE = environmentals('HERMES_GENERAL_ENDPOINT', 'http://Hermes:6000/')
    payload = {
        'channel': channel,
        'to': recipient,
        'subject': 'Verify Your Account',
        'data': {'code': code,'username': user.name},
        'idempotent_key': idempotent_key
    }
    try:
        response = requests.post(f"{MESSENGER_SERVICE}", json=payload)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error sending verification code: {e}")
        raise ConnectionError("Failed to send verification code.")
    
def _get_prodigy_id_by_email_or_telegram(user: User):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("SELECT prodigy_id FROM credentials WHERE email=%s OR telegram=%s", (user.email, user.telegram))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row: raise ValueError("User not found.")
    return row[0]

def get_prodigy_id(user: User) -> int:
    return _get_prodigy_id_by_email_or_telegram(user)

def _insert_otp(prodigy_id, purpose, channel, code_hash, ttl_minutes=10):
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
      INSERT INTO otp_tokens (id,prodigy_id,purpose,channel,code_hash,expires_at,attempts,sent_count,last_sent_at)
      VALUES (%s,%s,%s,%s,%s,%s,0,1,now())
    """, (str(uuid.uuid4()), prodigy_id, purpose, channel, code_hash, expires_at))
    conn.commit(); cur.close(); conn.close()

def attempt_verification(user: User, channel: str = '', purpose: str = 'reset') -> None:
    if not user.email and not user.telegram:
        raise ValueError("No contact information provided for verification.")
    if purpose == 'reset':
        checkUserExists(user, expected=True)
    code = f"{secrets.randbelow(1_000_000):06d}"  # 6-digit numeric
    idempotent_key = str(uuid.uuid4())
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    prodigy_id = _get_prodigy_id_by_email_or_telegram(user)
    _insert_otp(prodigy_id, purpose, channel or ('email' if user.email else 'telegram'), code_hash)
    # send via Messaging
    send_otp(user, code, idempotent_key, channel)

def verify_otp(user: User, code: str, purpose: str = 'reset', channel: str = '') -> None:
    prodigy_id = _get_prodigy_id_by_email_or_telegram(user)
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
      SELECT id, code_hash, expires_at, attempts, consumed_at
        FROM otp_tokens
       WHERE prodigy_id=%s AND purpose=%s AND (channel=%s OR %s='')
         AND consumed_at IS NULL
       ORDER BY expires_at DESC
       LIMIT 1
    """, (prodigy_id, purpose, channel or '', channel or ''))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        raise ValueError("Invalid or expired code.")
    oid, stored_hash, expires_at, attempts, consumed_at = row
    if datetime.now(timezone.utc) > expires_at:
        cur.close(); conn.close()
        raise ValueError("Invalid or expired code.")
    provided = hashlib.sha256(code.encode()).hexdigest()
    if not hmac.compare_digest(provided, stored_hash):
        cur.execute("UPDATE otp_tokens SET attempts=attempts+1 WHERE id=%s", (oid,))
        conn.commit(); cur.close(); conn.close()
        raise ValueError("Invalid or expired code.")
    cur.execute("UPDATE otp_tokens SET consumed_at=now() WHERE id=%s", (oid,))
    conn.commit(); cur.close(); conn.close()


def update_password(user: User) -> None:
    """
    Update the user's password in the database
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        user.password_check()
        hashed_password = hash_password(user.password)
        cursor.execute(
            "UPDATE credentials SET password = %s WHERE email = %s OR telegram = %s",
            (hashed_password, user.email, user.telegram)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error updating user password: {e}")
        raise RuntimeError("Failed to update user password.")

def decode_access_token(token: str):
    ISS = environmentals('JWT_ISS', 'Cerberus')
    AUD = environmentals('JWT_AUD', 'Prodigy')
    SECRET = environmentals('SECRET', '')
    return jwt.decode(token, SECRET, algorithms=["HS256"], audience=AUD, issuer=ISS,
        options={"require": ["exp", "iat", "nbf", "iss", "aud"]}
    )

def send_secret():
    SECRET = environmentals('SECRET', '')
    if not SECRET or len(SECRET) < 32:
        raise RuntimeError("SECRET must be set to a strong, >=32-byte value.")
    return SECRET

def assert_prodigy_exists(pid: str) -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM credentials WHERE prodigy_id=%s", (int(pid),))
        if cur.fetchone() is None:
            raise ValueError("User not found.")
        
def mark_user_verified(user: User) -> None:
    """
    Mark the user as verified in the database
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE credentials SET status = 'active' WHERE email = %s OR telegram = %s",
            (user.email, user.telegram)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error marking user as verified: {e}")
        raise RuntimeError("Failed to mark user as verified.")