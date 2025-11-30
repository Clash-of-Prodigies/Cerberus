# Cerberus Authentication Service

Cerberus is Prodigy’s authentication service. It handles registration, verification by OTP, login, password reset, token issuance and validation, logout, and signing key rotation. It is designed to be portable across stacks. Cryptographic choices, identifiers, and database contracts are framework-agnostic so you can reimplement the HTTP surface in a different language without changing storage or message formats.

---

## Highlights

* 9-digit `prodigy_id` as the only user identifier (random, non-guessable)
* JWT access tokens, RS256 signatures, `kid` header, short TTL cookie
* Token invalidation on password change by `token_version` and `password_changed_at`
* Hard revocation by access token `jti` (logout and abuse flow)
* Pending user flow with “re-register to resend OTP” and optional `/resend-verification`
* Registration and reset OTPs with 10 minute expiry, delivered by Hermes (messaging service)
* Rotating RSA keys with a single active key enforced by the database, grace window for retired keys
* Portable hashing and claims, no Python-only constructs in the storage contract
* Clean separation of concerns: Cerberus (auth API), Hermes (messaging), Postgres (storage)

---

## Endpoints

### `POST /register`

Create a pending user and send a registration OTP.

Body

```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "telegram": "123456789", 
  "password": "Password1!",
  "confirm_password": "Password1!",
  "channel": "email"
}
```

Responses

* `201` Registration Successful, OTP sent.
* `202` Verification code re-sent when an account already exists with status `pending`.
* `409` Account already exists and is active.

Notes

* A second call for the same email while still pending will resend the registration OTP rather than failing.

---

### `POST /forgot`

Dual use, controlled by payload:

* Verification of registration: set `purpose: "registration"` with `code`.
* Password reset: first call without `code` to send OTP, second call with `code` and new passwords.

Examples

```json
// start reset
{ "email": "jane@example.com", "channel": "email" }

// finish reset
{
  "email": "jane@example.com",
  "channel": "email",
  "code": "123456",
  "password": "NewPassw0rd!",
  "confirm_password": "NewPassw0rd!"
}

// verify registration
{
  "email": "jane@example.com",
  "channel": "email",
  "code": "654321",
  "purpose": "registration"
}
```

Responses

* `200` Success for verification or reset completion.
* `200` Generic success for “if an account exists we sent it” to avoid enumeration.

---

### `POST /login`

Exchanges credentials for a short-lived access token in an `HttpOnly` cookie named `jwt`.

Body

```json
{ "email": "jane@example.com", "password": "Password1!" }
```

Responses

* `200` Cookie set. Cookie attributes: `HttpOnly`, `SameSite=Lax`, `Secure=request.is_secure`, `Max-Age` matches `exp`.
* `401` If account is pending, the handler resends a registration OTP and returns a message instructing verification.

---

### `GET /dashboard` (example protected route)

Requires a valid access token. Either the `jwt` cookie or `Authorization: Bearer` works.

Responses

* `200` On success.
* `401` When missing token, expired token, revoked JTI, version mismatch, or older than password change (with skew).

---

### `POST /logout`

Revokes the current access token by inserting its `jti` into `revoked_access_jti`. Subsequent calls with that token fail.

Response: `200`

---

### `POST /admin/rotate-keys`

Rotate signing keys. Protected by `Authorization: Bearer <ADMIN_TOKEN>` and not internet-facing.

Body

```json
{ "bits": 2048, "grace_minutes": 45 }
```

Behavior

* Generates a new RSA keypair on disk, inserts the public key as `staging` in `keys`.
* Single-statement swap: retires the old active key, activates the new key, sets `verify_until` for the retired one.
* Writes the `ACTIVE_KID` file only after the DB row becomes `active`.
* Existing tokens with the previous `kid` continue to verify until `verify_until` passes.

Response: `200` with JSON `{ old_kid, new_kid, keys_dir, active_kid_file }`.

---

## Token model

Header

```json
{ "alg": "RS256", "typ": "JWT", "kid": "<uuid>" }
```

Claims

```json
{
  "sub": "<prodigy_id as string>",
  "iss": "Cerberus",
  "aud": "Prodigy",
  "iat": <unix>,
  "nbf": <unix>,
  "exp": <unix>,
  "jti": "<uuid>",
  "ver": <integer token_version>
}
```

Validation rules

* Signature verified using the public key from the `keys` table matched by `kid`.
* `iss` and `aud` must match configuration.
* `exp`, `nbf`, `iat` required. A small leeway (`CERBERUS_SKEW_SECS`, default 10 seconds) prevents false negatives under clock skew.
* If key `status` is `retired` and `verify_until` has passed, verification fails.
* `jti` rejected if present in `revoked_access_jti`.
* `ver` must match the current `token_version` in `credentials`.
* If `iat` is older than `password_changed_at` minus skew, reject.

---

## Database schema overview

All tables live in `public`. Roles: `prodigy_db_admin` (owner), `prodigy_db_app` (runtime).

* `credentials`

  * `prodigy_id BIGINT PRIMARY KEY DEFAULT gen_prodigy_id()` (9 digits)
  * `email TEXT UNIQUE (lower)`, `username TEXT UNIQUE (lower)`, `telegram TEXT (optional)`
  * `password TEXT` (store a proper hash like bcrypt or PBKDF2 from the app layer)
  * `status TEXT` in `('pending','active','disabled')`
  * `is_verified BOOLEAN`
  * `token_version INT DEFAULT 0`
  * `password_changed_at TIMESTAMPTZ DEFAULT now()`
  * triggers: update `updated_at`, bump `token_version` and `password_changed_at` on password change, purge `refresh_tokens` on password change

* `users`

  * Profile fields keyed by `prodigy_id` (FK to `credentials`)

* `otp_tokens`

  * `purpose` in `('registration','reset')`
  * `channel` in `('email','telegram')`
  * `code_hash`, `expires_at`, `consumed_at`, counts

* `refresh_tokens`

  * Rotation family support: `family_id`, `jti`, `token_hash`, `fingerprint`, `expires_at`, `revoked_at`
  * Present for completeness, even if you only use short-lived access tokens today

* `rate_limits`

  * Buckets like `ip:1.2.3.4` or `id:123456789`, with `fail_count`, cooldown and block windows

* `keys`

  * `kid TEXT PRIMARY KEY`, `alg TEXT` (RS256), `public_pem TEXT`
  * `status` in `('staging','active','retired')`
  * `activated_at`, `retired_at`, `verify_until`
  * partial unique index `one_active_key` on `status='active'`
  * trigger to stamp timestamps when status changes

* `revoked_access_jti`

  * Access token `jti` hard revocation list, with `expires_at` for garbage collection

* `messages` (Hermes outbox)

  * `channel`, `recipient`, `subject`, `data JSONB`, `status`, `attempts`, `last_error`, `idempotency_key`
  * general messaging surface retained for the messaging service

---

## Key rotation design

* Keys live on disk inside the Cerberus container (or a mounted volume).

  * `KEYS_DIR=/etc/cerberus/keys`
  * `ACTIVE_KID_FILE=/etc/cerberus/ACTIVE_KID`
* The database stores only the public key and lifecycle state.
* Rotation flow:

  1. Generate new RSA keypair, write PEMs to `KEYS_DIR/new_kid.{pem,pub}`.
  2. Insert new `kid` as `staging` in `keys`.
  3. Single-statement swap: retire the old `active` (fill `retired_at`, set `verify_until`), activate `new_kid` (fill `activated_at`).
  4. Write `ACTIVE_KID_FILE` with `new_kid`.
  5. New logins are signed with `new_kid`. Old tokens continue to pass until `verify_until`.

---

## Environment variables

* `DATABASE_URL` or separate `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`
* `JWT_ISS` (default `Cerberus`)
* `JWT_AUD` (default `Prodigy`)
* `CERBERUS_SKEW_SECS` (default `10`)
* `ADMIN_TOKEN` for `/admin/rotate-keys`
* `KEYS_DIR` (default `./keys` in dev)
* `ACTIVE_KID_FILE` (default `./ACTIVE_KID` in dev)
* Hermes endpoint variables as used by your `send_otp` helper

---

## Bootstrap on a fresh database

1. Start Postgres with the provided `init.sql`.
2. Start Cerberus with `KEYS_DIR` and `ACTIVE_KID_FILE` mapped to a persistent location, and `ADMIN_TOKEN` set.
3. Call rotation once to seed the first key row and `ACTIVE_KID`:

   ```bash
   curl -X POST http://127.0.0.1:5000/admin/rotate-keys \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"bits":2048,"grace_minutes":45}'
   ```
4. Register, verify, and log in.

If you already have a private key and `ACTIVE_KID`, insert the matching public key row into `keys` with status `active`.

---

## Testing

### Python end-to-end smoke

Covers registration, verification, login, dashboard, reset, old cookie fails after reset, logout and JTI revocation, rotation with grace, kid check, post-grace failure.

* Interactive:

  ```
  python smoke_e2e.py
  ```
* Pipe OTPs:

  ```
  printf "355488\n833006\n" | python smoke_e2e.py
  ```
* Env:

  ```
  REG_CODE=355488 RESET_CODE=833006 python smoke_e2e.py --grace-minutes 1
  ```

### Pending user flow smoke

Covers the “register, do not verify, re-register to resend, verify, login”.

* Interactive:

  ```
  python smoke_pending_registration.py
  ```
* Pipe one OTP:

  ```
  printf "123456\n" | python smoke_pending_registration.py
  ```

---

## Security notes

* Access tokens are short lived, sent only in an `HttpOnly` cookie. In production use HTTPS so `Secure` is true.
* Password changes bump `token_version` and `password_changed_at`. Existing access tokens die immediately, without waiting for expiry.
* Logout inserts the access token `jti` into `revoked_access_jti`.
* Registration and reset OTPs expire after 10 minutes. Rate limits can throttle repeated failures by IP and by identifier.
* Responses avoid leaking existence where practical. Registration and resend use generic wording when appropriate.

---

## Common issues and quick fixes

* **Invalid token right after login on a fresh DB**
  The `keys` table is empty. Call `/admin/rotate-keys` once to seed an active key row, or insert the public key for the current `ACTIVE_KID`.

* **Token has no `kid`**
  Ensure `jwt.encode(..., headers={"kid": active_kid})` in the signer.

* **Duplicate key value violates unique constraint "one_active_key"**
  Rotation tried to set a new key `active` before retiring the old one. Use the single-statement swap or retire first, then activate.

* **Token older than password change**
  Minor clock skew between DB and app. Keep `CERBERUS_SKEW_SECS` at 5 to 15 seconds. Versioning still blocks truly old tokens.

* **Cookie not sent on localhost**
  If you run over `http://`, do not force `Secure=True`. Use `secure=request.is_secure`. Also hit the same host you set the cookie for (use `localhost` or `127.0.0.1` consistently).

---

## Implementation notes

* Key generation uses JOSE (`jwcrypto`) to write PKCS#8 private PEM and SPKI public PEM. These formats are accepted by Java Nimbus, Node jose, Go crypto.
* Signing and verification use RS256. Public keys are stored in Postgres for verifiers and optional JWKS publishing later.
* Hashing is portable. Store a standard hash string (for example bcrypt or PBKDF2) in `credentials.password`. The choice does not affect the schema.
* Messaging is decoupled. Cerberus calls Hermes to deliver OTPs. `messages` table exists in the central DB as Hermes’ outbox.

---

## Future work

* Publish a read-only JWKS endpoint backed by `keys`, to allow other services to fetch public keys.
* Move smoke tests into pytest with fixtures and CI.
* Metrics for rate limiting, OTP success rate, revocation counts, and rotation events.
* Scheduled cleanup of expired OTPs, retired keys past `verify_until`, and old revocations.

---

## License and ownership

Cerberus is part of the Prodigy platform. Copyright remains with the project owner.
Contributors should follow the security and code review guidelines before merging any changes.
