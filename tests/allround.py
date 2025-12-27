#!/usr/bin/env python3
import base64
import json
import sys
import time
from types import SimpleNamespace

import requests

# From the outside, Cerberus lives at /auth behind Nginx.
# For example, with:
#   location /auth {
#       proxy_pass http://cerberus:5000;
#       ...
#   }
#
# All calls in this script go to https://.../auth/...
args = SimpleNamespace(
    base="https://sobbingly-hydrochloric-joel.ngrok-free.dev/auth",
    admin_token="qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm",
    email="oluwajuwonadedowole@gmail.com",
    telegram="6965644872",
    name="John Doe",
    pass1="Password1!",
    pass2="NewPassw0rd!",
    grace_minutes=1,
    post_grace_wait_seconds=70,
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
            return c.value or ""
    return ""


def print_title(msg: str) -> None:
    print(f"\n===== {msg} =====")


def read_otp(name: str) -> str:
    """
    Read a 6-digit OTP from stdin (if piped) or interactively.
    """
    if not sys.stdin.isatty():
        line = sys.stdin.readline().strip()
        if line and line.isdigit() and len(line) == 6:
            return line
        print(f"Error: expected a 6-digit {name} OTP on stdin", file=sys.stderr)
        sys.exit(1)

    while True:
        code = input(f"Enter {name} OTP (6 digits): ").strip()
        if code.isdigit() and len(code) == 6:
            return code
        print("Invalid code, must be exactly 6 digits.")


def expect_status(resp: requests.Response, want: int, label: str) -> None:
    ok = resp.status_code == want
    if ok:
        print(f"{label}: OK (HTTP {resp.status_code})")
        return

    print(f"{label}: HTTP {resp.status_code} (expected {want})")
    body = (resp.text or "")[:300].replace("\n", " ")
    print(f"  Response preview: {body}")
    raise SystemExit(f"Expected HTTP {want} for '{label}'")


def http_call(sess: requests.Session | None, method: str, path: str, label: str, **kwargs) -> requests.Response:
    """
    Wrapper around requests / session.request that:
      - builds full URL using BASE + path
      - logs method, URL, and JSON payload (truncated)
    """
    full_url = f"{BASE}{path}"
    print(f"{label}: {method} {full_url}")
    if "json" in kwargs and kwargs["json"] is not None:
        try:
            payload_str = json.dumps(kwargs["json"], indent=2)
            print(f"{label}: payload (json) =")
            print(payload_str[:400] + ("..." if len(payload_str) > 400 else ""))
        except TypeError:
            print(f"{label}: payload (json) present but not serializable for logging")

    if sess is None:
        resp = requests.request(method, full_url, **kwargs)
    else:
        resp = sess.request(method, full_url, **kwargs)
    return resp


def main():
    global BASE
    BASE = args.base.rstrip("/")
    ADMIN_TOKEN = args.admin_token

    print("=== Cerberus all-round integration test ===")
    print(f"BASE URL : {BASE}")
    print(f"Admin kid rotation token length: {len(ADMIN_TOKEN)}")
    print("This assumes Nginx is proxying /auth to the Cerberus service.\n")

    # Four sessions to simulate different client states
    SA = requests.Session()  # first login, becomes stale after password change
    SB = requests.Session()  # fresh login after password reset, then logout
    SC = requests.Session()  # login before rotation (token signed by old kid)
    SD = requests.Session()  # login after rotation (token signed by new kid)

    # 0) Rotate keys with a short grace window
    print_title(f"Rotate keys (grace {args.grace_minutes} minutes)")
    r = http_call(
        None,
        "POST",
        f"/admin/rotate-keys?token={ADMIN_TOKEN}",
        "rotate keys (initial)",
        json={"bits": 2048, "grace_minutes": args.grace_minutes},
    )
    expect_status(r, 200, "rotate keys (initial)")
    print(f"Rotate response: {r.text[:180]}")

    # 1) Register
    print_title("Register user")
    r = http_call(
        SA,
        "POST",
        "/register",
        "register",
        json={
            "name": args.name,
            "email": args.email,
            "telegram": args.telegram,
            "password": args.pass1,
            "confirm_password": args.pass1,
            "channel": "email",
        },
    )
    print(f"register: body preview: {r.text[:180]}")
    expect_status(r, 201, "register")

    # 2) Verify registration through /verify with purpose=registration
    print_title("Verify REGISTRATION with OTP")
    print("(Check Hermes output for the REGISTRATION OTP, then enter it here...)")
    reg_code = read_otp("registration")
    r = http_call(
        SA,
        "POST",
        "/verify",
        "verify registration",
        json={
            "email": args.email,
            "code": reg_code,
            "channel": "email",
            "purpose": "registration",
        },
    )
    print(f"verify registration: body preview: {r.text[:180]}")
    expect_status(r, 200, "verify registration")

    # 3) Login initial
    print_title("Login (initial)")
    r = http_call(
        SA,
        "POST",
        "/login",
        "login initial",
        json={"email": args.email, "password": args.pass1},
    )
    expect_status(r, 200, "login initial")

    # 4) Dashboard with initial cookie
    print_title("Dashboard with initial cookie (expect 200)")
    r = http_call(SA, "GET", "/dashboard", "dashboard initial")
    expect_status(r, 200, "dashboard initial")

    token_a = get_cookie_jwt(SA)
    print(f"JWT A (truncated): {token_a[:40]}...")
    hdr_a = decode_jwt_header(token_a)
    kid_a = hdr_a.get("kid", "")
    print(f"kid A: {kid_a or '<none>'}")

    # 5) Initiate password reset
    print_title("Initiate password reset")
    r = http_call(
        SA,
        "POST",
        "/verify",
        "forgot init",
        json={"email": args.email, "channel": "email"},
    )
    expect_status(r, 200, "forgot init")

    print("(Check Hermes output for the RESET OTP, then enter it here...)")
    reset_code = read_otp("reset")

    # 6) Complete password reset
    print_title("Complete password reset")
    r = http_call(
        SA,
        "POST",
        "/verify",
        "forgot complete",
        json={
            "email": args.email,
            "channel": "email",
            "code": reset_code,
            "password": args.pass2,
            "confirm_password": args.pass2,
        },
    )
    expect_status(r, 200, "forgot complete")

    # 7) Dashboard with OLD cookie after password change should be 401
    print_title("Dashboard with OLD cookie after password change (expect 401)")
    r = http_call(SA, "GET", "/dashboard", "dashboard old cookie")
    expect_status(r, 401, "dashboard old cookie")

    # 8) Login with NEW password
    print_title("Login with NEW password")
    r = http_call(
        SB,
        "POST",
        "/login",
        "login new pass",
        json={"email": args.email, "password": args.pass2},
    )
    expect_status(r, 200, "login new pass")

    print_title("Dashboard with NEW cookie (expect 200)")
    r = http_call(SB, "GET", "/dashboard", "dashboard new cookie")
    expect_status(r, 200, "dashboard new cookie")

    # 9) Logout, then dashboard should be 401
    print_title("Logout (revoke current JTI)")
    r = http_call(SB, "POST", "/logout", "logout")
    expect_status(r, 200, "logout")

    print_title("Dashboard after logout with same cookie (expect 401)")
    r = http_call(SB, "GET", "/dashboard", "dashboard after logout")
    expect_status(r, 401, "dashboard after logout")

    # 10) Login again to prepare for rotation
    print_title("Login again to prepare for key rotation")
    r = http_call(
        SC,
        "POST",
        "/login",
        "login pre-rotation",
        json={"email": args.email, "password": args.pass2},
    )
    expect_status(r, 200, "login pre-rotation")

    token_c = get_cookie_jwt(SC)
    hdr_c = decode_jwt_header(token_c)
    kid_before = hdr_c.get("kid", "")
    print(f"kid BEFORE rotation: {kid_before or '<none>'}")

    # 11) Rotate keys with a short grace window
    print_title(f"Rotate keys again (grace {args.grace_minutes} minutes)")
    r = http_call(
        None,
        "POST",
        f"/admin/rotate-keys?token={ADMIN_TOKEN}",
        "rotate keys (second)",
        json={"bits": 2048, "grace_minutes": args.grace_minutes},
    )
    expect_status(r, 200, "rotate keys (second)")
    print(f"Rotate response: {r.text[:180]}")

    # 12) Old token during grace should still work
    print_title("Old token during grace (expect 200)")
    r = http_call(SC, "GET", "/dashboard", "dashboard old token during grace")
    expect_status(r, 200, "dashboard old token during grace")

    # 13) Login after rotation to get a token with new kid
    print_title("Login after rotation")
    r = http_call(
        SD,
        "POST",
        "/login",
        "login post-rotation",
        json={"email": args.email, "password": args.pass2},
    )
    expect_status(r, 200, "login post-rotation")

    token_d = get_cookie_jwt(SD)
    hdr_d = decode_jwt_header(token_d)
    kid_after = hdr_d.get("kid", "")
    print(f"kid AFTER rotation: {kid_after or '<none>'}")

    if kid_before and kid_after and kid_before != kid_after:
        print("✅ kid changed after rotation")
    else:
        print("⚠️ kid did not change. Check rotate endpoint and ACTIVE_KID_FILE wiring.")

    # 14) Wait for grace window to elapse, then old token should fail
    wait_secs = int(args.post_grace_wait_seconds)
    print(f"\nSleeping ~{wait_secs}s so retired key grace window can elapse...")
    time.sleep(wait_secs)

    print_title("Old token after grace (expect 401)")
    r = http_call(SC, "GET", "/dashboard", "dashboard old token after grace")
    expect_status(r, 401, "dashboard old token after grace")

    print_title("New token still valid (expect 200)")
    r = http_call(SD, "GET", "/dashboard", "dashboard new token after grace")
    expect_status(r, 200, "dashboard new token after grace")

    print("\nDone. Summary:")
    print(f" kid before: {kid_before}")
    print(f" kid after : {kid_after}")


if __name__ == "__main__":
    main()
