"""
KingBank — a LAB-ONLY online bank (one of KINGNET's bundled targets).

Realistic: password + TOTP login, a real signed session cookie, an account balance,
payees, and money transfers that actually move the balance. The AiTM lesson here is the
scariest one: phish the login, steal the session, and from the attacker's own machine
**drain the account** — because to this bank, holding the session cookie *is* authority.

Then the defenses:
  * detection — a transfer from a new device/location (or to a brand-new payee) is flagged
    on /security, exactly like KingMail's cookie-replay detection;
  * step-up — an admin policy can require a fresh transaction authorization (TOTP) for
    payments, which a session thief does not have, so the fraud is refused.

It is NOT a real bank. Lab-only.
"""
import os
import time
import uuid

import pyotp
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

SECRET = os.environ.get("KINGBANK_SECRET", "kingnet-lab-kingbank-secret")
SESSION_COOKIE = "kingbank_session"
PENDING_COOKIE = "kingbank_pending"
LAB_DEFAULT_GEO = os.environ.get("KINGBANK_DEFAULT_GEO", "Johannesburg, ZA")

USERS = {
    "victim@kingbank.lab": {
        "password": "Autumn2026!",
        "name": "Vicky Target",
        "totp": "JBSWY3DPEHPK3PXP",  # fixed demo secret (same as the student's /phone)
        "account": "KB-1000",
        "balance": 75000.00,
        "payees": {"KB-1001": "Landlord (rent)", "KB-1002": "Mum"},
        "history": [{"to": "KB-1001", "name": "Landlord (rent)", "amount": 9500.00, "ts": time.time() - 86400}],
    }
}
MULE_HINT = "KB-9999"  # the account the lab attacker drains funds to

SESSIONS: dict[str, dict] = {}   # sid -> {email, created, fps:[...]}
ALERTS: list[dict] = []
POLICY = {"require_step_up": os.environ.get("KINGBANK_REQUIRE_STEP_UP", "") not in ("", "0", "false")}

app = FastAPI(title="KingBank (KINGNET lab target)")
tpl = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
signer = URLSafeTimedSerializer(SECRET)


def _sign(s): return signer.dumps(s)


def _unsign(tok, max_age):
    try:
        return signer.loads(tok, max_age=max_age)
    except (BadSignature, Exception):
        return None


def current_user(request: Request):
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


def _fp(request: Request) -> dict:
    return {"ua": request.headers.get("user-agent", "unknown"),
            "geo": request.headers.get("x-lab-geo", LAB_DEFAULT_GEO),
            "ip": request.client.host if request.client else "?"}


def _flag(email, sid, request, kinds):
    fp = _fp(request)
    ALERTS.insert(0, {"ts": time.time(), "email": email, "fp": fp, "anomalies": kinds})


def _access_anomalies(sid, request) -> list:
    sess = SESSIONS.get(sid)
    if not sess:
        return []
    fp = _fp(request)
    known = sess["fps"]
    if any(k["ua"] == fp["ua"] and k["geo"] == fp["geo"] for k in known):
        return []
    anomalies = []
    if all(k["ua"] != fp["ua"] for k in known):
        anomalies.append(("new device", fp["ua"][:60]))
    if all(k["geo"] != fp["geo"] for k in known):
        anomalies.append(("impossible travel", f"{known[0]['geo']} → {fp['geo']}"))
    known.append(fp)
    return anomalies


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return RedirectResponse("/dashboard" if current_user(request) else "/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str = ""):
    return tpl.TemplateResponse(request, "login.html", {"error": error})


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    u = USERS.get(email)
    if not u or u["password"] != password:
        return tpl.TemplateResponse(request, "login.html", {"error": "Incorrect login details."}, status_code=401)
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
    if not pyotp.TOTP(USERS[email]["totp"]).verify(code, valid_window=1):
        return tpl.TemplateResponse(request, "otp.html", {"error": "Invalid or expired code."}, status_code=401)
    sid = uuid.uuid4().hex
    SESSIONS[sid] = {"email": email, "created": time.time(), "fps": [_fp(request)]}
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie(SESSION_COOKIE, _sign(f"{email}|{sid}"), httponly=True, samesite="lax", max_age=3600)
    resp.delete_cookie(PENDING_COOKIE)
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, msg: str = "", error: str = ""):
    cu = current_user(request)
    if not cu:
        return RedirectResponse("/login", status_code=302)
    email, sid = cu
    u = USERS[email]
    return tpl.TemplateResponse(request, "dashboard.html", {
        "email": email, "name": u["name"], "account": u["account"], "balance": u["balance"],
        "payees": u["payees"], "history": list(reversed(u["history"])), "msg": msg, "error": error})


@app.post("/pay")
def pay(request: Request, payee: str = Form(...), amount: float = Form(...), code: str = Form("")):
    cu = current_user(request)
    if not cu:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    email, sid = cu
    u = USERS[email]

    # Defense knob: require a fresh transaction authorization (TOTP) for payments.
    # A session thief doesn't have the victim's authenticator, so this refuses the fraud.
    if POLICY["require_step_up"]:
        if not code or not pyotp.TOTP(u["totp"]).verify(code, valid_window=1):
            return JSONResponse({"error": "step-up authorization required", "step_up": True}, status_code=401)

    if amount <= 0 or amount > u["balance"]:
        return JSONResponse({"error": "invalid amount or insufficient funds"}, status_code=400)

    # Detection: is this payment coming from a new device/location, or to a new payee?
    anomalies = _access_anomalies(sid, request)
    if payee not in u["payees"]:
        anomalies.append(("new payee", f"first-ever transfer to {payee}"))
    u["balance"] = round(u["balance"] - amount, 2)
    u["history"].append({"to": payee, "name": u["payees"].get(payee, "NEW payee"),
                         "amount": amount, "ts": time.time()})
    if anomalies:
        _flag(email, sid, request, [("suspicious payment", f"R{amount:,.2f} to {payee}")] + anomalies)

    if "application/json" in request.headers.get("accept", "") or request.headers.get("x-api") == "1":
        return JSONResponse({"ok": True, "balance": u["balance"]})
    return RedirectResponse(f"/dashboard?msg=Sent+R{amount:.2f}+to+{payee}", status_code=302)


@app.get("/security", response_class=HTMLResponse)
def security(request: Request):
    return tpl.TemplateResponse(request, "security.html", {"alerts": ALERTS})


@app.post("/admin/policy")
async def admin_policy(request: Request):
    body = await request.json()
    POLICY["require_step_up"] = bool(body.get("require_step_up"))
    return {"require_step_up": POLICY["require_step_up"]}


@app.get("/phone", response_class=HTMLResponse)
def phone(request: Request):
    email = "victim@kingbank.lab"
    code = pyotp.TOTP(USERS[email]["totp"]).now()
    return HTMLResponse(f"<body style='font:20px sans-serif;text-align:center;padding:40px'>"
                        f"<h3>KingBank Authenticator</h3><p>Your code:</p>"
                        f"<div style='font-size:40px;font-weight:800;letter-spacing:4px'>{code}</div>"
                        f"<p style='color:#888'>(lab — refreshes every 30s)</p></body>")
