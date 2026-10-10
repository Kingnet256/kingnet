"""
KINGNET lab router — a Host-header reverse proxy so every org and campaign is reachable
in the browser by its real lab domain (e.g. http://acme-mail.kingnet.lab) instead of a
localhost port.

It listens on one port and forwards each request to the container whose Docker network
alias matches the request's Host. It is a plain pass-through (no capture — the AiTM proxy
does that); it only ever routes to `*.kingnet.lab` names on the isolated lab network, so it
can never reach a real service. Lab-only.
"""
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

LAB_SUFFIX = os.environ.get("LAB_SUFFIX", ".kingnet.lab")
UPSTREAM_PORT = os.environ.get("UPSTREAM_PORT", "8080")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "content-length",
              "content-encoding", "host"}

app = FastAPI(title="KINGNET lab router")
client = httpx.AsyncClient(follow_redirects=False, timeout=30.0)


@app.on_event("shutdown")
async def _close():
    await client.aclose()


@app.api_route("/{path:path}",
               methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def route(request: Request, path: str):
    if path == "healthz":                      # the CLI health-checks this regardless of Host
        return JSONResponse({"ok": True, "role": "lab-router"})

    host = request.headers.get("host", "").split(":")[0].lower()
    if not host.endswith(LAB_SUFFIX):
        return JSONResponse(
            {"error": f"'{host}' is not a lab host; the router only serves *{LAB_SUFFIX}"},
            status_code=404)

    # Forward to the container registered under this exact lab domain (Docker network alias).
    upstream = f"http://{host}:{UPSTREAM_PORT}/{path}"
    body = await request.body()
    up_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    up_headers["host"] = host
    try:
        r = await client.request(request.method, upstream, params=request.query_params,
                                 headers=up_headers, content=body)
    except Exception as e:
        return JSONResponse({"error": f"no backend for {host}: {e}"}, status_code=502)

    out_headers, set_cookies = {}, []
    for name, value in r.headers.multi_items():
        ln = name.lower()
        if ln in HOP_BY_HOP:
            continue
        if ln == "set-cookie":
            set_cookies.append(value)
            continue
        out_headers[name] = value
    resp = Response(content=r.content, status_code=r.status_code, headers=out_headers)
    for c in set_cookies:                      # preserve every Set-Cookie individually
        resp.raw_headers.append((b"set-cookie", c.encode("latin-1")))
    return resp
