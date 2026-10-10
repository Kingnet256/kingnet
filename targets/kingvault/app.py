"""
KingVault — a LAB-ONLY passkey-protected portal (KINGNET's DEFENSE demo).

Phase 3 upgrade: this now speaks REAL, standard WebAuthn (via the `webauthn` library),
so it works with a genuine browser passkey (navigator.credentials) AND with the scripted
software authenticator used by the tests — the same endpoints for both.

The point is unchanged: the same KINGNET AiTM proxy that fully owns KingMail cannot phish
KingVault, because a WebAuthn assertion is cryptographically bound to the ORIGIN the
browser is on. Relay it from the proxy (a different origin) and verification fails. The
origin check is enforced by `verify_authentication_response(expected_origin=...)` below.
Lab-only.
"""
import json
import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

SECRET = os.environ.get("KINGVAULT_SECRET", "kingnet-lab-kingvault-secret")
RP_ID = os.environ.get("KINGVAULT_RP_ID", "localhost")
RP_NAME = "KingVault"
EXPECTED_ORIGIN = os.environ.get("KINGVAULT_ORIGIN", "http://localhost:8082").rstrip("/")
SESSION_COOKIE = "kingvault_session"

app = FastAPI(title="KingVault (KINGNET lab target — real WebAuthn)")
tpl = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
signer = URLSafeTimedSerializer(SECRET)

# In-memory lab state (public keys only — the RP never sees the private key).
USERS: dict[str, dict] = {
    "victim@kingvault.lab": {"name": "Vicky Target", "credential_id": None,
                             "public_key": None, "sign_count": 0},
}
PENDING: dict[str, bytes] = {}  # username -> current challenge


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
    opts = generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME, user_name=username, user_display_name=USERS[username]["name"])
    PENDING[username] = opts.challenge
    # options_to_json gives the exact base64url JSON a browser's navigator.credentials wants.
    return JSONResponse(content=json.loads(options_to_json(opts)))


@app.post("/register/complete")
async def register_complete(request: Request):
    body = await request.json()
    username = body.get("username", "")
    challenge = PENDING.get(username)
    if username not in USERS or not challenge:
        return JSONResponse({"error": "no pending registration"}, status_code=400)
    try:
        v = verify_registration_response(
            credential=body["credential"], expected_challenge=challenge,
            expected_rp_id=RP_ID, expected_origin=EXPECTED_ORIGIN)
    except Exception as e:
        return JSONResponse({"error": f"registration failed: {e}"}, status_code=400)
    USERS[username].update(credential_id=v.credential_id, public_key=v.credential_public_key,
                           sign_count=v.sign_count)
    PENDING.pop(username, None)
    return {"ok": True}


# ---- WebAuthn authentication (log in with the passkey) ---------------------

@app.post("/login/begin")
async def login_begin(payload: dict):
    username = payload.get("username", "")
    u = USERS.get(username)
    if not u or not u.get("credential_id"):
        return JSONResponse({"error": "no passkey enrolled"}, status_code=404)
    opts = generate_authentication_options(
        rp_id=RP_ID, allow_credentials=[PublicKeyCredentialDescriptor(id=u["credential_id"])])
    PENDING[username] = opts.challenge
    return JSONResponse(content=json.loads(options_to_json(opts)))


@app.post("/login/complete")
async def login_complete(request: Request):
    body = await request.json()
    username = body.get("username", "")
    u = USERS.get(username)
    challenge = PENDING.get(username)
    if not u or not u.get("public_key") or not challenge:
        return JSONResponse({"error": "no pending login"}, status_code=400)
    try:
        v = verify_authentication_response(
            credential=body["credential"], expected_challenge=challenge,
            expected_rp_id=RP_ID, expected_origin=EXPECTED_ORIGIN,
            credential_public_key=u["public_key"], credential_current_sign_count=u["sign_count"],
            require_user_verification=False)
    except Exception as e:
        # The AiTM-defeat path: a relayed assertion lands here. The library's origin check
        # refuses it because clientDataJSON.origin is the phishing proxy, not us.
        PENDING.pop(username, None)
        return JSONResponse({"error": f"{e}", "phishing_resistant": True}, status_code=401)
    u["sign_count"] = v.new_sign_count
    PENDING.pop(username, None)
    resp = JSONResponse({"ok": True, "redirect": "/vault"})
    resp.set_cookie(SESSION_COOKIE, signer.dumps(username), httponly=True, samesite="lax", max_age=3600)
    return resp
