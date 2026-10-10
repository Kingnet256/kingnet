"""
KingVault — a LAB-ONLY "secure portal" that logs in with a PASSKEY (WebAuthn/FIDO2)
instead of password + OTP. It is KINGNET's DEFENSE demo: the exact same AiTM proxy
that fully owns KingMail cannot phish KingVault, because the passkey assertion is
cryptographically bound to the origin the victim's browser is actually on.

Flow (all real, just minimal — see webauthn_core.py):
  enroll:  POST /register/begin  -> POST /register/complete   (passkey bound to this origin)
  login:   POST /login/begin     -> POST /login/complete       (origin-bound assertion)
           success -> sets `kingvault_session` cookie -> /vault

The security-relevant checks live in webauthn_core.verify_assertion(): the signed
origin and RP-ID must match THIS service. Relay the assertion from a phishing proxy
(a different origin) and it is refused. Lab-only.
"""
import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

import webauthn_core as wa

SECRET = os.environ.get("KINGVAULT_SECRET", "kingnet-lab-kingvault-secret")
RP_ID = os.environ.get("KINGVAULT_RP_ID", "localhost")
EXPECTED_ORIGIN = os.environ.get("KINGVAULT_ORIGIN", "http://localhost:8082").rstrip("/")
SESSION_COOKIE = "kingvault_session"

app = FastAPI(title="KingVault (KINGNET lab target — passkey-protected)")
tpl = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
signer = URLSafeTimedSerializer(SECRET)

# In-memory lab state. Each user may enroll one passkey (public key only — the RP
# never sees the private key, same as real WebAuthn).
USERS: dict[str, dict] = {
    "victim@kingvault.lab": {"name": "Vicky Target", "credential_id": None, "public_key": None},
}
PENDING: dict[str, dict] = {}  # username -> {"challenge":..., "type":...}


def current_user(request: Request):
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        return None
    try:
        email = signer.loads(tok, max_age=3600)
    except (BadSignature, Exception):
        return None
    return email if email in USERS else None


@app.get("/healthz")
def healthz():
    return {"ok": True, "rp_id": RP_ID, "origin": EXPECTED_ORIGIN}


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return RedirectResponse("/vault" if current_user(request) else "/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return tpl.TemplateResponse(request, "login.html",
                                {"rp_id": RP_ID, "origin": EXPECTED_ORIGIN})


@app.get("/vault", response_class=HTMLResponse)
def vault(request: Request):
    email = current_user(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    return tpl.TemplateResponse(request, "vault.html",
                                {"email": email, "name": USERS[email]["name"]})


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ---- WebAuthn registration (enroll a passkey) ------------------------------

@app.post("/register/begin")
async def register_begin(payload: dict):
    username = payload.get("username", "")
    if username not in USERS:
        return JSONResponse({"error": "unknown user"}, status_code=404)
    challenge = wa.new_challenge()
    PENDING[username] = {"challenge": challenge, "type": "create"}
    return {"challenge": challenge, "rp_id": RP_ID, "origin": EXPECTED_ORIGIN, "username": username}


@app.post("/register/complete")
async def register_complete(payload: dict):
    username = payload.get("username", "")
    pend = PENDING.get(username)
    if not pend or pend.get("type") != "create":
        return JSONResponse({"error": "no pending registration"}, status_code=400)
    ok, reason = wa.verify_registration(
        expected_origin=EXPECTED_ORIGIN, expected_challenge=pend["challenge"],
        client_data_json=payload.get("client_data_json", ""))
    if not ok:
        return JSONResponse({"error": reason}, status_code=400)
    USERS[username]["credential_id"] = payload.get("credential_id")
    USERS[username]["public_key"] = payload.get("public_key_pem")
    PENDING.pop(username, None)
    return {"ok": True}


# ---- WebAuthn authentication (log in with the passkey) ---------------------

@app.post("/login/begin")
async def login_begin(payload: dict):
    username = payload.get("username", "")
    u = USERS.get(username)
    if not u or not u.get("credential_id"):
        return JSONResponse({"error": "no passkey enrolled"}, status_code=404)
    challenge = wa.new_challenge()
    PENDING[username] = {"challenge": challenge, "type": "get"}
    return {"challenge": challenge, "rp_id": RP_ID, "origin": EXPECTED_ORIGIN,
            "allow_credentials": [u["credential_id"]]}


@app.post("/login/complete")
async def login_complete(payload: dict):
    username = payload.get("username", "")
    u = USERS.get(username)
    pend = PENDING.get(username)
    if not u or not u.get("public_key") or not pend or pend.get("type") != "get":
        return JSONResponse({"error": "no pending login"}, status_code=400)

    assertion = {
        "credential_id": payload.get("credential_id"),
        "client_data_json": payload.get("client_data_json"),
        "authenticator_data": payload.get("authenticator_data"),
        "signature": payload.get("signature"),
    }
    ok, reason = wa.verify_assertion(
        public_key_pem=u["public_key"], expected_rp_id=RP_ID,
        expected_origin=EXPECTED_ORIGIN, expected_challenge=pend["challenge"],
        assertion=assertion)
    PENDING.pop(username, None)
    if not ok:
        # This is the AiTM-defeat path: a relayed assertion lands here and is refused.
        return JSONResponse({"error": reason, "phishing_resistant": True}, status_code=401)

    resp = JSONResponse({"ok": True, "redirect": "/vault"})
    resp.set_cookie(SESSION_COOKIE, signer.dumps(username), httponly=True, samesite="lax", max_age=3600)
    return resp
