import secrets, hashlib, hmac
from flask import Request, Response
from jwcrypto import jwk
from datetime import datetime, timezone, timedelta
from psycopg import Connection, connect as pg_connect
from psycopg.errors import OperationalError
from jwt import InvalidTokenError, ExpiredSignatureError

import os
import re
import requests
import bcrypt
import uuid
import jwt
import stat

class User:
    """
    User class to represent a user in the system
    """
    def __init__(self, **kwargs):
        self.email = kwargs.get('email', '')
        self.telegram = kwargs.get('telegram', '')
        self.password = kwargs.get('password', '')
        self.name = kwargs.get('username', '')
        self.fullName = kwargs.get('full-name', '')
        self.age = kwargs.get('age', 0)
        self.referralCode = kwargs.get('referrer', '')
        self.institution = kwargs.get('institution', '')
        self.acceptedTerms = kwargs.get('agreed', False)

    def check_before_entry(self):
        self.email = self._email_check()
        self.telegram = self._telegram_check()
        self.fullName = self._fullname_check()
        self.name = self._name_check()
        self.age = self._age_check()
        self.referralCode = self._referralCode_check()
        self.institution = self._insitution_check()
        self.acceptedTerms = self._accepted_terms_check()
        self._password_check()

    def _email_check(self) -> str:
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
                raise ValueError('Email verification service is unavailable! Contact support.')
        return email
    
    def _telegram_check(self) -> str:
        chat_id = self.telegram.strip()
        if chat_id and not re.fullmatch(r'-?(?:100)?\d{5,20}', chat_id):
            raise ValueError('Telegram chat id is not valid!')
        return chat_id

    def _password_check(self) -> None:
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
        self._password_check()
        if self.password != confirm_password:
            raise ValueError('Passwords do not match!')

    def _name_check(self) -> str:
        n = self.name.strip().lower()
        if len(n) < 5 or len(n) > 15:
            raise ValueError('Name must be 5–15 chars long.')
        if not re.fullmatch(r"[a-z0-9_ .-]{5,15}", n):
            raise ValueError('Name may contain alphanumeric, whitespace, underscore, period and hyphen.')
        return n

    def _fullname_check(self) -> str:
        # [A-Za-z]+(?:-[A-Za-z]+)*\s+[A-Za-z]+
        fn = self.fullName.strip()
        if len(fn) < 5 or len(fn) > 50:
            raise ValueError('Full name must be 5–50 chars long.')
        if not re.fullmatch(r"[A-Za-z]+(?:-[A-Za-z]+)*\s+[A-Za-z]+", fn):
            raise ValueError('Full name must have at least first and last name, letters and hyphens only.')
        return fn
    
    def _age_check(self) -> int:
        age = int(self.age)
        if age < 10 or age > 25:
            raise ValueError('Age must be between 10 and 25.')
        return age
    
    def _referralCode_check(self) -> str:
        code = self.referralCode.strip()
        if code and not re.fullmatch(r"[A-Z]{1,2}[0-9][0-9A-Z]?\s[0-9][A-Z]{2}", code):
            raise ValueError('Referral code must be 6 alphanumeric characters.')
        return code

    def _insitution_check(self) -> str:
        institution = self.institution.strip()
        if institution and len(institution) > 50:
            raise ValueError('Institution name must be less than 100 characters.')
        return institution
    
    def _accepted_terms_check(self) -> bool:
        if not self.acceptedTerms:
            raise ValueError('You must accept the terms and conditions.')
        return True
    
    def clear(self) -> None:
        """
        Clear all information stored in the user instance
        """
        self.email = ''
        self.password = ''
        self.name = ''
        self.fullName = ''
        self.age = 0
        self.referralCode = ''
        self.institution = ''
        self.acceptedTerms = False

def isNameAvailable(name: str, expected: bool = True):
    """
    Check if a username is available in the database
    """
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

def checkUserExists(user: User, expected: bool):
    row = None
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT status, username FROM credentials
                WHERE ((email=%s AND %s <> '') OR (telegram=%s AND %s <> ''))
                LIMIT 1""",
                (user.email, user.email, user.telegram, user.telegram)
            )
            row = cur.fetchone()

    exists = row is not None
    is_active = (row and row[0] == 'active')
    is_pending = (row and row[0] == 'pending')


    if expected != exists:
        if is_pending:
            attempt_verification(user, channel='', purpose='registration')
            raise ValueError("User is pending verification. A new OTP has been sent.")
        elif not is_active:
            raise ValueError("User is not active. Contact support.")
        else:
            raise ValueError("User or password is invalid!")
            # keep the password part so attackers can't enumerate valid users

def getUserPasswordHash(user: User) -> str:
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT password
          FROM credentials
         WHERE (email=%s   AND %s <> '')
            OR (telegram=%s AND %s <> '')
         LIMIT 1
    """, (user.email, user.email, user.telegram, user.telegram))
    row = cur.fetchone(); cur.close(); conn.close()
    if row: return row[0]
    raise ValueError("User or password is invalid.")


def registerUser(user: User):
    """
    Register a new user in the database
    """
    with get_connection() as conn:
        with conn.cursor() as cursor:
            hashed_password = hash_password(user.password)
            cursor.execute("""
                INSERT INTO credentials (username, email, telegram, referral_code, password)
                VALUES (%s, %s, %s, %s, %s) RETURNING prodigy_id""", 
                (user.name, user.email, user.telegram, user.referralCode, hashed_password)
            )
            row = cursor.fetchone()
            if not row: raise RuntimeError("Row not inserted.")
            prodigy_id = row[0]
            cursor.execute("""
                INSERT INTO users (prodigy_id, full_name, age, institution)
                VALUES (%s, %s, %s, %s)""",
                (prodigy_id, user.fullName, user.age, user.institution)
            )

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
    
def make_access_token(prodigy_id: str, ttl_minutes=60):
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())

    kid = get_active_kid()
    private_pem = _load_private_key_for_kid(kid)

    ISS = environmentals('JWT_ISS', 'Cerberus')
    AUD = environmentals('JWT_AUD', 'Prodigy')

    payload = {
        "sub": str(prodigy_id),
        "iss": ISS,
        "aud": AUD,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
        "jti": jti,
        "ver": _get_token_version(int(prodigy_id))[0],
    }

    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})

def send_message(user: User, data: dict[str, str], subject: str, idempotent_key: str, channel: str) -> None:
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
    MESSENGER_SERVICE = environmentals('MESSENGER_ENDPOINT', 'http://localhost:6000/')
    sender = environmentals('MESSENGER_SENDER_NAME', 'Prodigy <noreply@clashofprodigies.org>')
    payload = {
        'channel': channel,
        'to': user.email if channel == 'email' else user.telegram,
        'sender': sender,
        'subject': subject,
        'data': data,
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
    cur.execute("""
        SELECT prodigy_id
          FROM credentials
         WHERE (email=%s   AND %s <> '')
            OR (telegram=%s AND %s <> '')
         LIMIT 1
    """, (user.email, user.email, user.telegram, user.telegram))
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

def _update_otp(id, code_hash):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
      UPDATE otp_tokens
         SET code_hash=%s, expires_at=now()+interval '10 minutes', attempts=0,
             sent_count=sent_count+1, last_sent_at=now(), consumed_at=NULL
       WHERE id=%s
    """, (code_hash, id))
    conn.commit(); cur.close(); conn.close()

def _check_if_otp_was_consumed(prodigy_id, purpose, channel) -> str:
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
      SELECT id
        FROM otp_tokens
       WHERE prodigy_id=%s AND purpose=%s AND (channel=%s OR %s='')
       ORDER BY expires_at DESC
       LIMIT 1
    """, (prodigy_id, purpose, channel or '', channel or ''))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        return ''
    return row[0]



def _get_name_by_prodigy_id(prodigy_id: int) -> str:
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT username
          FROM credentials
         WHERE prodigy_id=%s
         LIMIT 1
    """, (int(prodigy_id),))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        raise ValueError("User not found.")
    return row[0]

def attempt_verification(user: User, channel: str = '', purpose: str = 'reset') -> None:
    if not user.email and not user.telegram:
        raise ValueError("No contact information provided for verification.")
    if purpose == 'reset':
        checkUserExists(user, expected=True)
    code = f"{secrets.randbelow(1_000_000):06d}"  # 6-digit numeric
    idempotent_key = str(uuid.uuid4())
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    prodigy_id = _get_prodigy_id_by_email_or_telegram(user)
    existing_otp_id = _check_if_otp_was_consumed(prodigy_id, purpose, channel)
    if existing_otp_id:
        _update_otp(existing_otp_id, code_hash)
    else:
        _insert_otp(prodigy_id, purpose, channel or ('email' if user.email else 'telegram'), code_hash)
    
    # send via Messaging service
    data = {'code': code}
    send_message(user, data, 'Verify Your Account', idempotent_key, channel)

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
    user._password_check()
    hashed = hash_password(user.password)
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
        UPDATE credentials
           SET password=%s
         WHERE (email=%s   AND %s <> '')
            OR (telegram=%s AND %s <> '')
    """, (hashed, user.email, user.email, user.telegram, user.telegram))
    conn.commit(); cur.close(); conn.close()


def decode_access_token(token: str):
    ISS = environmentals('JWT_ISS', 'Cerberus')
    AUD = environmentals('JWT_AUD', 'Prodigy')

    hdr = jwt.get_unverified_header(token)
    kid = hdr.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("Missing kid")

    public_pem, status, verify_until, alg = _get_public_key_row(kid)
    if alg != "RS256":
        raise jwt.InvalidTokenError("Unsupported alg")
    if status not in ("active", "retired"):
        raise jwt.InvalidTokenError("Key not usable for verification")
    if status == "retired" and verify_until is not None:
        # reject if past the grace cutoff
        if datetime.now(timezone.utc) > verify_until:
            raise jwt.InvalidTokenError("Retired key no longer accepted")

    return jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        audience=AUD,
        issuer=ISS,
        options={"require": ["exp", "iat", "nbf", "iss", "aud"]},
        leeway=5
    )


def verify_jwt_token(req: Request) -> dict:
    # Prefer Bearer over cookie, so API calls from SPAs work even if cookies aren't sent
    auth = req.headers.get("Authorization", "")
    token = None
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        token = req.cookies.get("jwt")

    if not token:
        raise InvalidTokenError("Missing token")

    # decode with small leeway to avoid false negatives on nbf/iat
    claims = decode_access_token(token)  # ensure this uses leeway=5..10s

    sub = claims["sub"]
    assert_prodigy_exists(sub)

    # 1) JTI revocation
    jti = claims.get("jti")
    if jti and is_access_jti_revoked(jti):
        raise InvalidTokenError("Token revoked")

    # 2) Version + password-change cutoff with skew
    ver_claim = int(claims.get("ver", -1))
    ver_db, pw_cutoff, iat = get_user_token_guard(sub, int(claims["iat"]))
    if ver_claim != ver_db:
        raise InvalidTokenError("Token superseded")

    skew = 10
    if iat < (pw_cutoff - timedelta(seconds=skew)):
        raise InvalidTokenError("Token older than password change")

    return {
        "active": True,
        "sub": sub,
        "jti": claims.get("jti"),
        "ver": ver_claim,
        "iat": claims.get("iat"),
        "exp": claims.get("exp"),
    }


def extract_token_and_bearer_from_request(req: Request) -> tuple[str, str]:
    auth = req.headers.get("Authorization", "")
    cookie_token = req.cookies.get("jwt")
    if auth.startswith("Bearer ") and cookie_token:
        bearer = auth.split(" ", 1)[1].strip()
        token = cookie_token
        return token, bearer
    raise ValueError("No token or bearer was provided")

def send_secret():
    CERBERUS_SECRET = environmentals('CERBERUS_SECRET', '')
    if not CERBERUS_SECRET or len(CERBERUS_SECRET) < 32:
        raise RuntimeError("CERBERUS SECRET must be set to a strong, >=32-byte value.")
    return CERBERUS_SECRET

def assert_prodigy_exists(pid: str) -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM credentials WHERE prodigy_id=%s", (int(pid),))
        if cur.fetchone() is None:
            raise ValueError("User not found.")
        
def mark_user_verified(user: User) -> None:
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
        UPDATE credentials
           SET status='active'
         WHERE (email=%s   AND %s <> '')
            OR (telegram=%s AND %s <> '')
    """, (user.email, user.email, user.telegram, user.telegram))
    conn.commit(); cur.close(); conn.close()
    send_message(user, {}, 'Welcome to Prodigy!', str(uuid.uuid4()), channel='email' if user.email else 'telegram')

def is_access_jti_revoked(jti: str) -> bool:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM revoked_access_jti WHERE jti=%s", (jti,))
        return cur.fetchone() is not None

def get_user_token_guard(prodigy_id: str, iat: int) -> tuple[int, datetime, datetime]:
    iat_tz = datetime.fromtimestamp((iat), tz=timezone.utc)
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
          SELECT token_version, password_changed_at
            FROM credentials
           WHERE prodigy_id=%s
        """, (int(prodigy_id),))
        row = cur.fetchone()
        if not row:
            raise ValueError("User not found.")
        ver_db = int(row[0])
        pw_cutoff = row[1]
        # ensure tz-aware UTC
        if pw_cutoff.tzinfo is None:
            pw_cutoff = pw_cutoff.replace(tzinfo=timezone.utc)
        else:
            pw_cutoff = pw_cutoff.astimezone(timezone.utc)
        return ver_db, pw_cutoff, iat_tz

def revoke_access_jti(jti: str, pid: int, exp_ts: int) -> None:
    if not jti:
        return
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO revoked_access_jti (jti, prodigy_id, expires_at)
        VALUES (%s, %s, to_timestamp(%s))
        ON CONFLICT (jti) DO NOTHING
        """, (jti, int(pid), int(exp_ts)))
    conn.commit(); cur.close(); conn.close()


def delete_refresh_tokens(pid: int) -> None:
    conn = get_connection(); cur = conn.cursor()
    cur.execute("DELETE FROM refresh_tokens WHERE prodigy_id=%s", (int(pid),))
    conn.commit(); cur.close(); conn.close()

def _get_token_version(prodigy_id: int) -> tuple[int, datetime]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
          SELECT token_version, password_changed_at
            FROM credentials
           WHERE prodigy_id=%s
        """, (prodigy_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError("User not found.")
        return row[0], row[1]


def rotate_keys(body={}):
    """
    Rotates JWT signing keys.
    Body (JSON, all optional):
      bits: int (default 2048)
      grace_minutes: int (default 45)  grace window for accepting the retired key
      kid: string (default uuid4)      supply to control filename and kid
    """
    bits, grace_minutes, new_kid = resolve_rotate_keys_auth(body)
        
        # 1) generate keypair in-process (PEM strings), then write to disk
    private_pem, public_pem = gen_rsa_pair(new_kid, bits=bits)
    write_key_files(new_kid, private_pem, public_pem)

        # 2) insert public key as 'staging'
    _insert_staging_key(new_kid, public_pem)

        # 3) switch signer to new kid and flip statuses
    resp = _promote_and_retire(new_kid, grace_minutes)
    _write_active_kid(new_kid)
    return resp

def gen_rsa_pair(kid: str, bits: int = 2048, passphrase: str | None = None) -> tuple[str, str]:
    key = jwk.JWK.generate(kty="RSA", size=bits, kid=kid, use="sig", alg="RS256")

    # PKCS#8 private PEM
    if passphrase:
        priv_bytes = key.export_to_pem(private_key=True, password=passphrase.encode("utf-8"))
    else:
        priv_bytes = key.export_to_pem(private_key=True, password=None)

    # SPKI public PEM
    pub_bytes = key.export_to_pem(private_key=False)

    return priv_bytes.decode("utf-8"), pub_bytes.decode("utf-8")

def write_key_files(kid: str, private_pem: str, public_pem: str) -> tuple[str, str]:
    keys_dir = environmentals("KEYS_DIR", "./keys")
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, f"{kid}.pem")
    pub_path  = os.path.join(keys_dir, f"{kid}.pub")

    with open(priv_path, "w", encoding="utf-8") as f:
        f.write(private_pem)
    with open(pub_path, "w", encoding="utf-8") as f:
        f.write(public_pem)

    # chmod 600 on the private key
    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)
    return priv_path, pub_path

def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _write_active_kid(kid: str):
    ACTIVE_KID_FILE = environmentals("ACTIVE_KID_FILE", "./ACTIVE_KID")
    os.makedirs(os.path.dirname(ACTIVE_KID_FILE), exist_ok=True)
    with open(ACTIVE_KID_FILE, "w", encoding="utf-8") as f:
        f.write(kid.strip())

def _get_current_active_kid():
    # read from DB, not from file, so we know who to retire
    conn = get_connection(); cur = conn.cursor()
    cur.execute("SELECT kid FROM keys WHERE status='active' LIMIT 1")
    row = cur.fetchone()
    cur.close(); conn.close()
    return row[0] if row else None

def _promote_and_retire(new_kid: str, grace_minutes: int = 45) -> dict:
    verify_until_ts = datetime.now(timezone.utc) + timedelta(minutes=grace_minutes)
    conn = get_connection(); cur = conn.cursor()
    try:
        # serialize concurrent rotations
        cur.execute("SELECT pg_advisory_xact_lock(hashtext('rotate-keys'))")

        # retire old active and activate new in one statement
        cur.execute("""
            UPDATE keys
               SET status = CASE
                              WHEN kid = %s THEN 'active'
                              WHEN status = 'active' THEN 'retired'
                              ELSE status
                            END,
                   activated_at = CASE WHEN kid = %s THEN now() ELSE activated_at END,
                   retired_at    = CASE WHEN status='active' AND kid <> %s THEN now() ELSE retired_at END,
                   verify_until  = CASE
                                      WHEN status='active' AND kid <> %s THEN %s
                                      ELSE verify_until
                                   END
             WHERE kid = %s OR status = 'active'
        """, (new_kid, new_kid, new_kid, new_kid, verify_until_ts, new_kid))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close(); conn.close()
        return {
            "message": "Rotation complete",
            "new_kid": new_kid,
            "keys_dir": environmentals("KEYS_DIR", "./keys"),
            "active_kid_file": environmentals("ACTIVE_KID_FILE", "./ACTIVE_KID"),
            "grace_minutes": grace_minutes,
            "verify_until": verify_until_ts.isoformat(),
            "previous_active_kid": _get_current_active_kid(),
        }

def get_active_kid() -> str:
    ACTIVE_KID_FILE = environmentals("ACTIVE_KID_FILE", "./ACTIVE_KID")
    kid_file = ACTIVE_KID_FILE
    if os.path.exists(kid_file):
        return open(kid_file, "r", encoding="utf-8").read().strip()
    raise RuntimeError("ACTIVE_KID_FILE not found; cannot sign tokens")

def _load_private_key_for_kid(kid: str) -> str:
    KEYS_DIR = environmentals("KEYS_DIR", "./keys")
    path = os.path.join(KEYS_DIR, f"{kid}.pem")
    if not os.path.exists(path):
        raise RuntimeError(f"Private key for kid={kid} not found")
    return open(path, "r", encoding="utf-8").read()

def _get_public_key_row(kid: str):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""
       SELECT public_pem, status, verify_until, alg
         FROM keys
        WHERE kid=%s
        LIMIT 1
    """, (kid,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        raise ValueError("Unknown key id")
    return row  # public_pem, status, verify_until, alg


def _insert_staging_key(kid: str, public_pem: str):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO keys (kid, alg, public_pem, status, created_at)
                VALUES (%s, 'RS256', %s, 'staging', now())
                ON CONFLICT (kid) DO NOTHING""",
                (kid, public_pem)
            )
        conn.commit()

def resolve_rotate_keys_auth(request: dict) -> tuple[int, int, str]:
    bits = int(request.get("bits", 2048))
    grace_minutes = int(request.get("grace_minutes", 45))
    new_kid = request.get("kid") or str(uuid.uuid4())
    return bits, grace_minutes, new_kid