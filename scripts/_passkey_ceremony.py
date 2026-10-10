"""
Phase 2 proof — drives the passkey ceremony as the victim's browser would, against
KingVault directly (honest) and THROUGH the KINGNET proxy (AiTM), and asserts the
AiTM relay is refused. Invoked by scripts/passkey_test.sh (servers must be up).

The one faithful detail: a real browser signs the origin of the page the user is on.
So the direct client signs KingVault's origin; the proxied client signs the proxy's
origin. KingVault accepts the first and rejects the second.
"""
import os
import sys

import httpx

ROOT = os.environ["KINGNET_ROOT"]
sys.path.insert(0, os.path.join(ROOT, "targets", "kingvault"))
import webauthn_core as wa  # noqa: E402

KV = os.environ.get("KV_ORIGIN", "http://localhost:8082")
PX = os.environ.get("PROXY_ORIGIN", "http://localhost:8445")
CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:9000")
USER = "victim@kingvault.lab"

auth = wa.SoftAuthenticator()  # the victim's authenticator (phone/laptop/YubiKey)
ok_all = True


def check(cond, msg):
    global ok_all
    print(("  \033[1;32m✓\033[0m " if cond else "  \033[1;31m✗\033[0m ") + msg)
    if not cond:
        ok_all = False


print("\n== enroll a passkey on the REAL site (origin %s) ==" % KV)
with httpx.Client(timeout=15) as c:
    o = c.post(f"{KV}/register/begin", json={"username": USER}).json()
    pk = auth.create(o["rp_id"])
    cdj = wa.build_client_data("webauthn.create", o["challenge"], KV)
    r = c.post(f"{KV}/register/complete", json={
        "username": USER, "credential_id": pk.credential_id,
        "public_key_pem": pk.public_key_pem(), "client_data_json": cdj})
    check(r.status_code == 200 and r.json().get("ok"), f"passkey enrolled (HTTP {r.status_code})")

print("\n== HONEST login on the real origin — should SUCCEED ==")
with httpx.Client(timeout=15) as c:
    o = c.post(f"{KV}/login/begin", json={"username": USER}).json()
    a = auth.get_assertion(o["allow_credentials"][0], KV, o["rp_id"], o["challenge"])
    r = c.post(f"{KV}/login/complete", json={"username": USER, **a})
    check(r.status_code == 200, f"login accepted (HTTP {r.status_code})")
    check("kingvault_session" in r.cookies, "real session cookie issued to the user")

print("\n== AiTM: same passkey, but the victim is on the PROXY (origin %s) ==" % PX)
with httpx.Client(timeout=15) as c:
    o = c.post(f"{PX}/login/begin", json={"username": USER}).json()
    # The browser signs the origin it is actually on — the proxy's.
    a = auth.get_assertion(o["allow_credentials"][0], PX, o["rp_id"], o["challenge"])
    r = c.post(f"{PX}/login/complete", json={"username": USER, **a})
    body = r.json()
    check(r.status_code == 401, f"relayed assertion REJECTED by the real service (HTTP {r.status_code})")
    check(body.get("phishing_resistant") is True, "service marks the attempt phishing-resistant")
    check("ORIGIN MISMATCH" in body.get("error", ""), f"reason → {body.get('error','')[:78]}")
    check("kingvault_session" not in r.cookies, "NO session cookie leaked to the attacker")

print("\n== attacker console — what did the proxy get? ==")
dash = httpx.get(f"{CONSOLE}/", timeout=15).text
check("attack FAILED" in dash, "console shows the passkey attack FAILED")
check("REJECTED" in dash, "console shows the captured assertion is useless to replay")

print("\nRESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
