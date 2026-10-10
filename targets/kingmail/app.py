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
import uuid

import pyotp
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

SECRET = os.environ.get("KINGMAIL_SECRET", "kingnet-lab-kingmail-secret")
SESSION_COOKIE = "kingmail_session"
PENDING_COOKIE = "kingmail_pending"

# ---- Phase 2 detection: a server-side session store that fingerprints each login.
# TOTP did NOT stop the AiTM theft, but the stolen cookie is replayed from the
# attacker's own machine — a different device, in a different place. We fingerprint
# each session at issuance and raise alerts when the SAME cookie shows up from a new
# fingerprint (new device / impossible travel / token reuse from two endpoints).
# `X-Lab-Geo` is a lab stand-in for a real GeoIP lookup; absent = the victim's ISP.
SESSIONS: dict[str, dict] = {}   # sid -> {email, created, fps: [fingerprint,...]}
ALERTS: list[dict] = []          # newest first
LAB_DEFAULT_GEO = os.environ.get("KINGMAIL_DEFAULT_GEO", "Johannesburg, ZA")

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
    """Return (email, sid) for a valid session, else None. The sid must exist in the
    server-side store — like a real session, not just a validly-signed value."""
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        return None
    val = _unsign(tok, max_age=3600)
    if not val or "|" not in val:
        return None
    email, sid = val.split("|", 1)
    if email not in USERS or sid not in SESSIONS:
        return None
    return email, sid


def _client_fp(request: Request) -> dict:
    return {
        "ua": request.headers.get("user-agent", "unknown"),
        "geo": request.headers.get("x-lab-geo", LAB_DEFAULT_GEO),
        "ip": request.client.host if request.client else "?",
    }


def _record_access(sid: str, request: Request) -> list:
    """Compare this request's fingerprint to the ones seen on this session; raise
    alerts for anything new. Returns the anomalies for THIS request (for a banner)."""
    sess = SESSIONS.get(sid)
    if not sess:
        return []
    fp = _client_fp(request)
    known = sess["fps"]
    if any(k["ua"] == fp["ua"] and k["geo"] == fp["geo"] for k in known):
        return []  # a device+place we've already seen on this session — fine
    anomalies = []
    if all(k["ua"] != fp["ua"] for k in known):
        anomalies.append(("new device", fp["ua"][:60]))
    if all(k["geo"] != fp["geo"] for k in known):
        anomalies.append(("impossible travel", f"{known[0]['geo']} → {fp['geo']} within seconds"))
    anomalies.append(("session token reuse", "the same session cookie is now in use from a second client"))
    known.append(fp)
    ALERTS.insert(0, {"ts": time.time(), "sid": sid, "email": sess["email"],
                      "fp": fp, "anomalies": anomalies})
    return anomalies


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
    # Record the issuing device/location so a later replay can be spotted.
    sid = uuid.uuid4().hex
    SESSIONS[sid] = {"email": email, "created": time.time(), "fps": [_client_fp(request)]}
    resp = RedirectResponse("/inbox", status_code=302)
    resp.set_cookie(SESSION_COOKIE, _sign(f"{email}|{sid}"), httponly=True, samesite="lax", max_age=3600)
    resp.delete_cookie(PENDING_COOKIE)
    return resp


@app.get("/inbox", response_class=HTMLResponse)
def inbox(request: Request):
    cu = current_user(request)
    if not cu:
        return RedirectResponse("/login", status_code=302)
    email, sid = cu
    alerts = _record_access(sid, request)  # flags a hijack replay from a new client
    u = USERS[email]
    return tpl.TemplateResponse(request, "inbox.html",
                                {"email": email, "name": u["name"], "mails": u["inbox"], "alerts": alerts})


@app.get("/security", response_class=HTMLResponse)
def security(request: Request):
    """Account security activity — where defenders (and the student) see the replay
    get caught, even though the 2FA login itself looked legitimate."""
    return tpl.TemplateResponse(request, "security.html", {"alerts": ALERTS})


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
