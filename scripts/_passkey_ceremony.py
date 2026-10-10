"""
Phase 3 proof — drives REAL, standard WebAuthn as the victim's browser would, using a
software authenticator (soft-webauthn) against the exact endpoints the browser UI uses.
Enrols a passkey, logs in honestly (succeeds), then relays the login through the KINGNET
proxy (must fail: the assertion is bound to the proxy's origin). Invoked by passkey_test.sh.
"""
import base64
import os
import sys

import httpx
from soft_webauthn import SoftWebauthnDevice

KV = os.environ.get("KV_ORIGIN", "http://localhost:8082")
PX = os.environ.get("PROXY_ORIGIN", "http://localhost:8445")
CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:9000")
USER = "victim@kingvault.lab"

dev = SoftWebauthnDevice()  # the victim's authenticator (phone/laptop/YubiKey)
ok_all = True


def check(cond, msg):
    global ok_all
    print(("  \033[1;32m✓\033[0m " if cond else "  \033[1;31m✗\033[0m ") + msg)
    if not cond:
        ok_all = False


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ser(resp_obj, fields):
    r = resp_obj["response"]
    out = {k: b64e(r[k]) for k in fields if r.get(k) is not None}
    return {"id": b64e(resp_obj["rawId"]), "rawId": b64e(resp_obj["rawId"]),
            "type": resp_obj["type"], "clientExtensionResults": {}, "response": out}


print("\n== enroll a passkey on the REAL site (origin %s) ==" % KV)
with httpx.Client(timeout=15) as c:
    o = c.post(f"{KV}/register/begin", json={"username": USER}).json()
    pkcco = {"publicKey": {
        "rp": o["rp"],
        "user": {**o["user"], "id": b64d(o["user"]["id"])},
        "challenge": b64d(o["challenge"]),
        "pubKeyCredParams": o["pubKeyCredParams"],
    }}
    att = dev.create(pkcco, KV)
    cred = ser(att, ["clientDataJSON", "attestationObject"])
    r = c.post(f"{KV}/register/complete", json={"username": USER, "credential": cred})
    check(r.status_code == 200 and r.json().get("ok"), f"passkey enrolled (HTTP {r.status_code})")


def do_login(base, origin, client):
    o = client.post(f"{base}/login/begin", json={"username": USER}).json()
    pkcro = {"publicKey": {
        "challenge": b64d(o["challenge"]), "rpId": o["rpId"],
        "allowCredentials": [{"id": b64d(a["id"]), "type": a["type"]} for a in o.get("allowCredentials", [])],
        "userVerification": o.get("userVerification", "preferred"),
    }}
    asr = dev.get(pkcro, origin)
    cred = ser(asr, ["clientDataJSON", "authenticatorData", "signature", "userHandle"])
    return client.post(f"{base}/login/complete", json={"username": USER, "credential": cred})


print("\n== HONEST login on the real origin — should SUCCEED ==")
with httpx.Client(timeout=15) as c:
    r = do_login(KV, KV, c)
    check(r.status_code == 200, f"login accepted (HTTP {r.status_code})")
    check("kingvault_session" in r.cookies, "real session cookie issued to the user")

print("\n== AiTM: same passkey, but the victim is on the PROXY (origin %s) ==" % PX)
with httpx.Client(timeout=15) as c:
    r = do_login(PX, PX, c)  # browser signs the proxy origin it is actually on
    body = r.json()
    check(r.status_code == 401, f"relayed assertion REJECTED by the real service (HTTP {r.status_code})")
    check(body.get("phishing_resistant") is True, "service marks the attempt phishing-resistant")
    check("origin" in body.get("error", "").lower(), f"reason → {body.get('error','')[:80]}")
    check("kingvault_session" not in r.cookies, "NO session cookie leaked to the attacker")

print("\n== attacker console — what did the proxy get? ==")
dash = httpx.get(f"{CONSOLE}/", timeout=15).text
check("attack FAILED" in dash, "console shows the passkey attack FAILED")
check("REJECTED" in dash, "console shows the captured assertion is useless to replay")

print("\nRESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
