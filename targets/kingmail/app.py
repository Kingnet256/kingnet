"""
KingMail — a LAB-ONLY webmail service (one of KINGNET's bundled targets).

It is deliberately realistic: real password login, real TOTP 2-factor, and a real
signed session cookie — so the AiTM attack against it is faithful, NOT a toy.
It only exists inside the KINGNET lab. It is NOT a real mail service.

Flow:  /login (password)  ->  /otp (TOTP)  ->  sets `kingmail_session` cookie  ->  /inbox
Helper: /phone shows the victim's current 6-digit code (simulates their authenticator app).
"""
import os
import time

import pyotp
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

SECRET = os.environ.get("KINGMAIL_SECRET", "kingnet-lab-kingmail-secret")
SESSION_COOKIE = "kingmail_session"
PENDING_COOKIE = "kingmail_pending"

# Seeded lab "victim" account. TOTP secret is fixed so the student can read codes
# from /phone (their simulated authenticator). All lab-only, obviously.
USERS = {
    "victim@kingmail.lab": {
        "password": "Summer2026!",
        "name": "Vicky Target",
        "totp": "JBSWY3DPEHPK3PXP",  # fixed demo secret
        "inbox": [
            {"from": "it-support@kingmail.lab", "subj": "Action required: verify your mailbox", "body": "Please re-verify your account to avoid suspension."},
            {"from": "ceo@kingcorp.lab", "subj": "Wire approval (confidential)", "body": "Approve the R450,000 transfer to the new supplier today."},
            {"from": "no-reply@kingbank.lab", "subj": "Your statement is ready", "body": "Your October e-statement is now available."},
        ],
    }
}

app = FastAPI(title="KingMail (KINGNET lab target)")
tpl = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
signer = URLSafeTimedSerializer(SECRET)


def _sign(data: str) -> str:
    return signer.dumps(data)


def _unsign(tok: str, max_age: int):
    try:
        return signer.loads(tok, max_age=max_age)
    except (BadSignature, Exception):
        return None


def current_user(request: Request):
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        return None
    email = _unsign(tok, max_age=3600)
    return email if email in USERS else None


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if current_user(request):
        return RedirectResponse("/inbox", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str = ""):
    return tpl.TemplateResponse(request, "login.html", {"error": error})


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    u = USERS.get(email)
    if not u or u["password"] != password:
        return tpl.TemplateResponse(request, "login.html", {"error": "Incorrect email or password."}, status_code=401
        )
    # password OK -> require 2FA. Stash a short-lived pending token.
    resp = RedirectResponse("/otp", status_code=302)
    resp.set_cookie(PENDING_COOKIE, _sign(email), httponly=True, samesite="lax", max_age=300)
    return resp


@app.get("/otp", response_class=HTMLResponse)
def otp_form(request: Request, error: str = ""):
    pending = request.cookies.get(PENDING_COOKIE)
    if not pending or not _unsign(pending, max_age=300):
        return RedirectResponse("/login", status_code=302)
    return tpl.TemplateResponse(request, "otp.html", {"error": error})


@app.post("/otp")
def otp(request: Request, code: str = Form(...)):
    pending = request.cookies.get(PENDING_COOKIE)
    email = _unsign(pending, max_age=300) if pending else None
    if not email or email not in USERS:
        return RedirectResponse("/login", status_code=302)
    totp = pyotp.TOTP(USERS[email]["totp"])
    if not totp.verify(code, valid_window=1):
        return tpl.TemplateResponse(request, "otp.html", {"error": "Invalid or expired code."}, status_code=401
        )
    # 2FA OK -> issue the real session cookie (the prize an AiTM attacker steals).
    resp = RedirectResponse("/inbox", status_code=302)
    resp.set_cookie(SESSION_COOKIE, _sign(email), httponly=True, samesite="lax", max_age=3600)
    resp.delete_cookie(PENDING_COOKIE)
    return resp


@app.get("/inbox", response_class=HTMLResponse)
def inbox(request: Request):
    email = current_user(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    u = USERS[email]
    return tpl.TemplateResponse(request, "inbox.html", {"email": email, "name": u["name"], "mails": u["inbox"]}
    )


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/phone", response_class=HTMLResponse)
def phone(request: Request):
    """Simulated authenticator app — shows the victim's current code so the
    student (playing the victim) knows what to type during the lesson."""
    email = "victim@kingmail.lab"
    totp = pyotp.TOTP(USERS[email]["totp"])
    code = totp.now()
    remaining = 30 - int(time.time()) % 30
    return tpl.TemplateResponse(request, "phone.html", {"code": code, "remaining": remaining, "email": email}
    )
