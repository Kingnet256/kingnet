# KINGNET — Ops / Work Log
_Newest on top. See DESIGN.md for the full plan._

### 2026-10-09 — Phase 1 MVP finished + verified end-to-end ✅
- **Green-lit Phase 1** (Python/FastAPI + Docker Compose stack confirmed; first scenario = KingMail login+OTP). Picked up the partial scaffold from earlier in the day and finished it.
- **Fixed a blocking bug:** every `TemplateResponse(...)` used the old Starlette signature `TemplateResponse("name.html", {"request": ...})`. Under Starlette 1.7.0 that passes the template name where `request` is expected → `TypeError: unhashable type: 'dict'` → HTTP 500 on every page. Rewrote all 8 calls (6 in `targets/kingmail/app.py`, 2 in `console/app.py`) to `TemplateResponse(request, "name.html", {...})`.
- **Fixed a proxy cookie bug:** response was built with `headers=dict(out_headers)`, which collapsed multiple `Set-Cookie` headers to the last one — so the post-2FA response (set session cookie + clear pending cookie) never actually logged the victim in. Now forwards every `Set-Cookie` intact via `resp.raw_headers`. (Attacker capture was unaffected; it reads upstream headers directly.)
- **Wrote `scripts/local_test.sh`** — a Docker-free runner (launches the 3 services from `.venv`, detached so they don't hold the shell pipe) that drives the full AiTM chain and asserts every stage. Doubles as the project smoke test (non-zero exit if any stage breaks).
- **Verified end-to-end (all stages PASS):** proxied login → credentials captured → live TOTP relayed → real session cookie stolen **and** forwarded so the victim is genuinely logged in → attacker console replays the cookie → victim's inbox opens with no password and no 2FA. No Docker on this box, so verification ran via `local_test.sh`.
- **Wrote `README.md`** (public-facing, GitHub/kasspar.com-ready) with a prominent LAB-ONLY banner, the safety boundary, component map, both Docker and no-Docker quick starts, the lab victim creds, and roadmap status. Added `data/.gitkeep` so the compose volume path survives; confirmed `.gitignore` covers `*.db` / `*.pyc` / logs / `.venv`.
- **Status:** Phase 0 + Phase 1 complete. Not yet committed to git / pushed (awaiting your go). Next: Phase 2 (passkey target that resists KINGNET + detection signals + guided lessons).

### 2026-10-09 — Project kickoff + design agreed
- Agreed scope: our own lab-contained AiTM/phishing **education** range (NOT an evilginx clone). Real techniques (cred/session/cookie capture, OTP relay, 2FA bypass, session hijack) against KINGNET's OWN bundled realistic lab targets only; never real external services; proxy hard-constrained to lab targets; lab-only DNS.
- Wrote DESIGN.md (vision, safety boundary, architecture, phased roadmap, guardrails).
- Awaiting: stack confirmation + green light to scaffold Phase 1 (KingMail login+OTP AiTM MVP).
