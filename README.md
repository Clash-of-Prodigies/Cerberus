# Cerberus (Prodigy Auth)

A portable, secure authentication service for **Prodigy**. This document captures the current design and on-wire contracts so you can implement it in Python, Spring Boot, Node, Go, or any other stack with the same behavior.

---

## 1) Goals

* Register users, authenticate users, reset passwords.
* Work across stacks using **JWT** (RS256) with **JWKS** for verification.
* Clean separation of concerns: **Cerberus** issues and validates tokens, a separate **Messaging** service sends OTPs, a separate **Database** service stores data.
* Strong security with short-lived access tokens, refresh tokens with rotation, OTP verification, and clear rate limits.
* Cerberus listens on local or internal interfaces only, but is built as if Internet exposed.

---

## 2) Components

* **Cerberus (Auth API)**: signs access JWTs, issues and rotates refresh tokens, manages OTP verification, enforces rate limits.
* **Messaging service**: delivers OTPs to email and WhatsApp, tracks send status.
* **Database service**: stores credentials, OTPs, refresh tokens, keys, and rate limit state.
* **Resource services**: verify access JWTs locally via JWKS, no DB calls needed for access checks.

---

## 3) Identifiers

* **Prodigy ID**: a **9-digit** random integer in the range `100000000..999999999`, unique and hidden from other users.

  * Generated with a cryptographically secure RNG.
  * Consider also accepting **email** or **username** during login to reduce lockouts.
* **User ID**: a UUID used internally and as the `sub` claim in JWTs.

---

## 4) Token model

* **Access JWT**: RS256, short lived (recommend 15–30 minutes, 60 max if you accept the gap).
  Claims: `sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti` (plus optional `roles`, `scope`).
* **Refresh token**: opaque random string, returned as `"<jti>.<secret>"`.
  Stored **hashed** (SHA-256 of `secret`) in the DB. Rotated on every use. Reuse detection supported through a `family_id`.

**No access-time DB call is required to validate an access JWT**. Resource services verify offline using JWKS.

---

## 5) Endpoints (JSON in, JSON out)

Use these names to stay consistent across stacks.

* `POST /registration`
  Create unverified user, send OTPs to email and WhatsApp. Response is always generic.

* `POST /authentication`
  Login with `prodigy_id` (or email or username if allowed) and `password`. Return an access JWT (and a cookie for browsers if you choose cookies).

* `POST /reset`
  Two roles in one endpoint.

  * **Initiate**: `{ prodigy_id, email, username }` (generic success) then send OTPs.
  * **Complete**: `{ prodigy_id, code, channel, new_password, confirm_password }` (consume OTP, set new password, revoke refresh families).

* `POST /validation`
  Cheap introspection for first-party clients. Verifies signature and standard claims only, no DB call.

* `POST /token/refresh`
  Rotate a refresh token and issue a new access token and refresh token.

* `POST /.well-known/jwks.json` (GET in practice)
  Public keys for RS256 verification.

* `POST /logout` (optional but recommended)
  Revoke the supplied refresh token (and its family). You can also add the current access `jti` to a short-lived blocklist if you implement hard access revocation.

---

## 6) Request and response examples

### Authentication

**Request**

```json
POST /authentication
{
  "prodigy_id": "123456789",
  "password": "CorrectHorseBatteryStaple!"
}
```

**Success**

```json
{
  "ok": true,
  "access_token": "<jwt>",
  "expires_in": 1800
}
```

**Failure** (generic)

```json
{ "message": "Invalid credentials" }
```

### Token refresh

**Request**

```json
POST /token/refresh
{
  "refresh_token": "b1b2b3b4-...-...Abc123.xyzVeryLongSecret"
}
```

**Success**

```json
{
  "ok": true,
  "access_token": "<new-jwt>",
  "expires_in": 1800,
  "refresh_token": "<rotated-refresh>"
}
```

### Reset (complete)

**Request**

```json
POST /reset
{
  "prodigy_id": "123456789",
  "channel": "email",
  "code": "204981",
  "new_password": "NewStrongPassword!23",
  "confirm_password": "NewStrongPassword!23"
}
```

**Success**

```json
{ "ok": true }
```

---

## 7) JWT details

**Algorithm**: RS256
**Header**:

```json
{ "alg": "RS256", "kid": "<current_kid>", "typ": "JWT" }
```

**Claims**:

```json
{
  "sub": "2a9e5c3e-...-...",
  "iss": "https://auth.prodigy.local",
  "aud": "api://prodigy",
  "iat": 1734048000,
  "nbf": 1734048000,
  "exp": 1734049800,
  "jti": "b4b2c4b0-...-...",
  "scope": "openid profile",
  "roles": ["user"]
}
```

**Verification rules in resource services**

* Verify signature against JWKS.
* Require `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, and `sub`.
* Enforce `aud` and any `scope` or `roles` required by the endpoint.

---

## 8) OTP policy

* 6 digits, random, single use.
* **TTL**: 10 minutes.
* Store **SHA-256(code)**, never the raw code.
* Increment `attempts` on each submit, expire after too many tries, require resend with cooldown.

---

## 9) Rate limiting policy

* Track per **IP** and per **identifier** (`id:123456789`), apply the stricter one.
* After **3 consecutive failures**, apply a cooldown that doubles: 1, 2, 4, 8, 16, 32 minutes.
* If cooldown reaches **32 minutes**, block key for **1 day**.
* Reset counters on success or after a quiet period.
* OTP resend cooldown: recommend 60 seconds, with a daily cap.

---

## 10) Password storage and policy

Pick a portable algorithm and use it in all stacks.

* **bcrypt** (cost 12), or
* **PBKDF2-HMAC-SHA256** (310k iterations).

Store a single encoded string that includes parameters. Never log or store plaintext passwords. Enforce a server side floor for length and complexity.

---

## 11) Data model (five tables, one optional)

> Names are illustrative. Use UUIDs for primary keys unless noted. Types are portable to Postgres, MySQL, and SQLite with minor changes.

### `credentials`

* `user_id` (UUID, PK)
* `prodigy_id` (BIGINT, unique, not null)
* `email` (TEXT, unique, lowercased)
* `username` (TEXT, unique)
* `password_hash` (TEXT, not null)
* `is_verified` (BOOLEAN, default false)
* Profile fields: `first_name`, `last_name`, `dob`, `sex`, `university`, `degree`, `program`, `subject_rankings` (JSON), `referral_code`
* `tos_version`, `tos_accepted_at`, `privacy_version`, `privacy_accepted_at`
* `created_at`, `updated_at`

### `otp_tokens`

* `id` (UUID, PK), `user_id` (FK credentials)
* `purpose` (`registration` or `reset`), `channel` (`email` or `wa`)
* `code_hash` (TEXT), `expires_at`, `consumed_at`, `attempts`, `sent_count`, `last_sent_at`

### `refresh_tokens`

* `id` (UUID, PK), `user_id` (FK credentials)
* `family_id` (UUID), `jti` (UUID, unique)
* `token_hash` (TEXT, sha256 of secret), `fingerprint` (TEXT, optional)
* `issued_at`, `expires_at`, `revoked_at` (nullable)

### `rate_limits`

* `key` (TEXT, PK, for example `ip:1.2.3.4` or `id:123456789`)
* `fail_count`, `cooldown_until`, `blocked_until`, `updated_at`

### `keys`

* `kid` (TEXT, PK), `alg` (TEXT, RS256)
* `public_pem` (TEXT), `status` (`staging`, `active`, `retired`)
* `created_at`, `activated_at`, `retired_at`

### Optional `revoked_access_jti`

Only if you need to kill access tokens before they expire.

* `jti` (UUID, PK), `user_id`, `expires_at`, `revoked_at`

**Private keys are not stored in the DB**. Keep them in a secrets store or a protected filesystem path.

---

## 12) Refresh token rotation and reuse detection

* Client holds `"<jti>.<secret>"`. Server stores `sha256(secret)` only.
* On refresh: verify, **set `revoked_at` on the old row**, issue a new refresh with the **same `family_id`** and a new `jti` and secret.
* If an old refresh is used later, treat this as **reuse** and revoke the entire `family_id` (logout that device family).

---

## 13) Key rotation procedure

1. Insert new key metadata in `keys` with `status = staging`.
2. Publish its public key in JWKS (`/.well-known/jwks.json`).
3. Start signing with the new `kid` and mark `status = active`.
4. After the longest access token expires, mark the old key `retired` and remove it from JWKS.

---

## 14) Transport, cookies, and CORS

* Cerberus is local or internal only, still use TLS where possible. Unix sockets are also fine on the same host.
* Browsers: if you set cookies, use `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, `Max-Age` aligned to access token `exp`.
* If you rely on cookies, validate `Origin` or `Referer` on state changing requests.
* Set strict CORS to exact front end origins. Do not use wildcards with credentials.

---

## 15) Error handling and privacy

* Use generic errors for login, registration resend, and reset initiate. Do not reveal whether an ID or email exists.
* Never log passwords, OTPs, or raw tokens. Log request ids, `sub`, `jti`, result codes, and coarse device info if needed.
* Uniform error envelope, for example `{ "message": "Invalid credentials" }` or `{ "error": { "code": "RATE_LIMIT", "retry_after": 60 } }`.

---

## 16) Observability and ops

* Metrics: login success and failure, OTP send and verify rates, refresh rotation counts, rate limit triggers.
* Tracing: correlate Messaging sends with OTP records.
* Config from environment variables or a secrets manager. No hard coded secrets.
* Debug mode off in production.

---

## 17) Example curl sequence (browserless)

```bash
# 1) Register (server responds generically, sends OTPs)
curl -X POST http://cerberus.local/registration \
  -H "content-type: application/json" \
  -d '{"first_name":"Ben","last_name":"A.","email":"ben@ex.com","username":"ben",
       "dob":"2004-05-12","sex":"M","university":"DSU","degree":"BS","program":"Cyber",
       "subject_rankings":["Math","Physics","Chemistry","Biology"],
       "referral_code":"ABC123", "tos_version":"v1","privacy_version":"v1"}'

# 2) Complete reset (same shape used for registration validation if you merge flows)
curl -X POST http://cerberus.local/reset \
  -H "content-type: application/json" \
  -d '{"prodigy_id":"123456789","channel":"email","code":"204981",
       "new_password":"NewStrongPassword!23","confirm_password":"NewStrongPassword!23"}'

# 3) Authenticate
curl -X POST http://cerberus.local/authentication \
  -H "content-type: application/json" \
  -d '{"prodigy_id":"123456789","password":"NewStrongPassword!23"}'

# 4) Refresh
curl -X POST http://cerberus.local/token/refresh \
  -H "content-type: application/json" \
  -d '{"refresh_token":"<jti>.<secret>"}'
```

---

## 18) Portability notes

* JWT and JWKS are language neutral.
* Password hashing choices are portable: **bcrypt 12** or **PBKDF2-SHA256 310k**.
* OTP storage uses **SHA-256** and timestamps, available in all stacks.
* Rate limit algorithm can live in SQL or Redis. Use the same keys and timers in any runtime.

---

## 19) Known tradeoffs

* With access tokens only, you cannot revoke before expiry. Refresh tokens and short access TTLs mitigate this.
* A 9-digit Prodigy ID is still guessable in theory, but hidden identifiers, generic errors, strong backoff, and IP rate limits reduce risk.
* Cerberus is local only today, still build like an Internet service to handle lateral movement.

---

## 20) Quick checklist

* [ ] RS256 signing, JWKS served, `kid` in header
* [ ] Access TTL 15–30 min, refresh 30–60 days with idle timeout
* [ ] Refresh rotation with `family_id`, reuse detection
* [ ] OTP 6 digits, 10 min TTL, hashed at rest
* [ ] Rate limits per IP and per identifier, doubling cooldown, 1 day block at 32 minutes
* [ ] Password hashing (bcrypt 12 or PBKDF2 310k)
* [ ] Generic errors, no enumeration
* [ ] Cookies secure for browsers, strict CORS
* [ ] Keys table for rotation metadata, private keys in a secrets store
* [ ] Logging without secrets, metrics in place

---

This README is the source of truth for behavior and contracts. Implementations in Python, Spring Boot, Node, or Go should follow it exactly so that Prodigy services can interoperate without changes.
