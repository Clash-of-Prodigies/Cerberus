#!/usr/bin/env python3
import base64
import json
import sys
import time
from types import SimpleNamespace

import requests

args = SimpleNamespace(
    base="http://127.0.0.1:5000",
    admin_token="qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm",
    email="name@example.com",
    telegram="123456789",
    name="John Doe",
    pass1="Password1!",
    pass2="NewPassw0rd!",
    grace_minutes= 1,
    post_grace_wait_seconds= 70,
)

def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad)


def decode_jwt_header(jwt_token: str) -> dict:
    try:
        header_b64 = jwt_token.split(".", 1)[0]
        return json.loads(b64url_decode(header_b64).decode("utf-8"))
    except Exception:
        return {}


def get_cookie_jwt(sess: requests.Session) -> str:
    # cookie name is 'jwt'
    for c in sess.cookies:
        if c.name == "jwt":
            return c.value or ''
    return ''


def print_title(msg: str) -> None:
    print(f"\n===== {msg} =====")


def read_otp(name: str) -> str:
    """
    stdin (if piped), then interactive prompt.
    """

    # If not a TTY, try to read a single line from stdin
    if not sys.stdin.isatty():
        line = sys.stdin.readline().strip()
        if line and line.isdigit() and len(line) == 6:
            return line
        print(f"Error: expected a 6-digit {name} OTP on stdin", file=sys.stderr)
        sys.exit(1)

    # Interactive prompt
    while True:
        code = input(f"Enter {name} OTP (6 digits): ").strip()
        if code.isdigit() and len(code) == 6:
            return code
        print("Invalid code, must be exactly 6 digits.")


def expect_status(resp: requests.Response, want: int, label: str) -> None:
    ok = resp.status_code == want
    print(f"{label}: HTTP {resp.status_code}")
    if not ok:
        # print a little body snippet to help
        body = (resp.text or "")[:300].replace("\n", " ")
        print(f"  Response preview: {body}")
        raise SystemExit(f"Expected HTTP {want} for '{label}'")


def main():
    BASE = args.base.rstrip("/")
    ADMIN_TOKEN = args.admin_token

    # Four sessions to simulate different client states
    SA = requests.Session()  # first login, becomes stale after password change
    SB = requests.Session()  # fresh login after password reset, then logout
    SC = requests.Session()  # login before rotation (token signed by old kid)
    SD = requests.Session()  # login after rotation (token signed by new kid)

    # 0) Rotate keys with a short grace window
    print_title(f"Rotate keys (grace {args.grace_minutes} minutes)")
    r = requests.post(f"{BASE}/admin/rotate-keys?token={ADMIN_TOKEN}",
                      json={"bits": 2048, "grace_minutes": args.grace_minutes})
    expect_status(r, 200, "rotate keys")
    print(f"Rotate response: {r.text[:180]}")

    # 1) Register
    print_title("Register user")
    r = SA.post(f"{BASE}/register", json={
        "name": args.name,
        "email": args.email,
        "telegram": args.telegram,
        "password": args.pass1,
        "confirm_password": args.pass1,
        "channel": "email",
    })
    print(f"Body: {r.text[:180]}")
    expect_status(r, 201, "register")

    # 2) Verify registration through /forgot with purpose=registration
    print_title("Verify REGISTRATION with OTP")
    print("(Check your Hermes mock output for the REGISTRATION OTP...)")
    reg_code = read_otp("registration")
    r = SA.post(f"{BASE}/forgot", json={
        "email": args.email,
        "code": reg_code,
        "channel": "email",
        "purpose": "registration",
    })
    print(f"Body: {r.text[:180]}")
    expect_status(r, 200, "verify registration")

    # 3) Login initial
    print_title("Login (initial)")
    r = SA.post(f"{BASE}/login", json={"email": args.email, "password": args.pass1})
    expect_status(r, 200, "login initial")

    # 4) Dashboard with initial cookie
    print_title("Dashboard with initial cookie (expect 200)")
    r = SA.get(f"{BASE}/dashboard")
    expect_status(r, 200, "dashboard initial")

    token_a = get_cookie_jwt(SA)
    print(f"JWT A: {token_a[:20]}...")
    hdr_a = decode_jwt_header(token_a)
    kid_a = hdr_a.get("kid", "")
    print(f"kid A: {kid_a or '<none>'}")

    # 5) Initiate password reset
    print_title("Initiate password reset")
    r = SA.post(f"{BASE}/forgot", json={"email": args.email, "channel": "email"})
    expect_status(r, 200, "forgot init")

    print("(Check your Hermes mock output for the RESET OTP...)")
    reset_code = read_otp("reset")

    # 6) Complete password reset
    print_title("Complete password reset")
    r = SA.post(f"{BASE}/forgot", json={
        "email": args.email,
        "channel": "email",
        "code": reset_code,
        "password": args.pass2,
        "confirm_password": args.pass2,
    })
    expect_status(r, 200, "forgot complete")

    # 7) Dashboard with OLD cookie after password change should be 401
    print_title("Dashboard with OLD cookie after password change (expect 401)")
    r = SA.get(f"{BASE}/dashboard")
    expect_status(r, 401, "dashboard old cookie")

    # 8) Login with NEW password
    print_title("Login with NEW password")
    r = SB.post(f"{BASE}/login", json={"email": args.email, "password": args.pass2})
    expect_status(r, 200, "login new pass")

    print_title("Dashboard with NEW cookie (expect 200)")
    r = SB.get(f"{BASE}/dashboard")
    expect_status(r, 200, "dashboard new cookie")

    # 9) Logout, then dashboard should be 401
    print_title("Logout (revoke current JTI)")
    r = SB.post(f"{BASE}/logout")
    expect_status(r, 200, "logout")

    print_title("Dashboard after logout with same cookie (expect 401)")
    r = SB.get(f"{BASE}/dashboard")
    expect_status(r, 401, "dashboard after logout")

    # 10) Login again to prepare for rotation
    print_title("Login again to prepare for key rotation")
    r = SC.post(f"{BASE}/login", json={"email": args.email, "password": args.pass2})
    expect_status(r, 200, "login pre-rotation")

    token_c = get_cookie_jwt(SC)
    hdr_c = decode_jwt_header(token_c)
    kid_before = hdr_c.get("kid", "")
    print(f"kid BEFORE: {kid_before or '<none>'}")

    # 11) Rotate keys with a short grace window
    print_title(f"Rotate keys (grace {args.grace_minutes} minutes)")
    r = requests.post(f"{BASE}/admin/rotate-keys?token={ADMIN_TOKEN}",
                      json={"bits": 2048, "grace_minutes": args.grace_minutes})
    expect_status(r, 200, "rotate keys")
    print(f"Rotate response: {r.text[:180]}")

    # 12) Old token during grace should still work
    print_title("Old token during grace (expect 200)")
    r = SC.get(f"{BASE}/dashboard")
    expect_status(r, 200, "dashboard old token during grace")

    # 13) Login after rotation to get a token with new kid
    print_title("Login after rotation")
    r = SD.post(f"{BASE}/login", json={"email": args.email, "password": args.pass2})
    expect_status(r, 200, "login post-rotation")

    token_d = get_cookie_jwt(SD)
    hdr_d = decode_jwt_header(token_d)
    kid_after = hdr_d.get("kid", "")
    print(f"kid AFTER: {kid_after or '<none>'}")

    if kid_before and kid_after and kid_before != kid_after:
        print("✅ kid changed after rotation")
    else:
        print("⚠️ kid did not change. Check rotate endpoint and ACTIVE_KID_FILE wiring.")

    # 14) Wait for grace window to elapse, then old token should fail
    wait_secs = int(args.post_grace_wait_seconds)
    print(f"\nSleeping ~{wait_secs}s so retired key grace elapses ...")
    time.sleep(wait_secs)

    print_title("Old token after grace (expect 401)")
    r = SC.get(f"{BASE}/dashboard")
    expect_status(r, 401, "dashboard old token after grace")

    print_title("New token still valid (expect 200)")
    r = SD.get(f"{BASE}/dashboard")
    expect_status(r, 200, "dashboard new token after grace")

    print("\nDone. Summary:")
    print(f" kid before: {kid_before}")
    print(f" kid after : {kid_after}")


if __name__ == "__main__":
    main()
