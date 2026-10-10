# 8 · Stealing the session without a proxy

AiTM isn't the only way to get the session cookie. Two very common routes don't touch the
network at all — they attack the victim's **browser**.

## Variant 1 — Cross-site scripting (XSS)
If an attacker can get their JavaScript to run on the page (a reflected or stored injection),
that script can read `document.cookie` and send it anywhere.

Try it: set your KingMail status to a script payload, then view the inbox.
```bash
./scripts/cookie_theft_test.sh      # runs the whole thing, asserted
```
The lab "browser" runs the injected script and ships `document.cookie` to the attacker's
drop server (the console's `/steal`). Note what it gets:
- ✅ it **steals** `kingmail_prefs` — a convenience cookie set **without** HttpOnly;
- ❌ it **cannot** see `kingmail_session` — that cookie is **HttpOnly**, so page JS is blind to it.

**Defenses:** mark session cookies **HttpOnly** (JS can't read them); **encode output** so
injected markup renders as text, not code (the lab's XSS-safe mode escapes the payload and
nothing runs); and add a **Content-Security-Policy** to block injected/inline scripts.

## Variant 2 — Infostealer / malicious extension
Malware or a sketchy browser extension doesn't run *in the page* — it reads the browser's
**cookie store on disk**. HttpOnly is a *page-JS* restriction, so it does **nothing** here:
the stealer lifts the HttpOnly session straight out of the store and replays it → account
takeover.

**Defense — device-bound sessions (DBSC / token binding):** bind the session to a key that
lives in the device's secure hardware and never leaves it. The server only honours the
cookie when the request proves possession of that key. In the lab, once binding is on, the
copied cookie is **refused** from any other machine — the stealer grabbed the cookie but not
the key. Shorter sessions + step-up re-auth on sensitive actions reduce the blast radius too.

## The takeaway
"Steal the session" has many doors: a proxy (AiTM), the page (XSS), or the endpoint
(infostealer). HttpOnly closes the XSS door for the session but not the malware door —
which is why the industry is moving to **device-bound credentials** and **phishing-resistant
passkeys**, so the cookie isn't a bearer token anyone can copy and reuse.
