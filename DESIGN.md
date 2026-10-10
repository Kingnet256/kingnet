# KINGNET — Lab-Contained AiTM / Phishing Education Framework

_Our own framework (not an evilginx clone). A realistic, hands-on cyber range that
demonstrates exactly how modern phishing / adversary-in-the-middle (AiTM) attacks
really work — then how to defend. Fully isolated: the techniques are real, the
targets are lab-only, and it can never reach a real service. For GitHub + kasspar.com._
_Started 2026-10-09._

## Vision
Students install KINGNET on their own computer (one command), and inside an isolated
lab they SEE the real attack chain happen against realistic services: a convincing
login is proxied, credentials are captured, the live OTP is relayed, the **real
session cookie is stolen**, and the attacker replays it to hijack the session —
bypassing 2FA. Then the lab shows how to STOP it (phishing-resistant MFA/passkeys).
Nothing is faked or dumbed down — only the *targets* are contained.

## The safety boundary (this is the whole point)
- **Attack techniques: REAL and fully functional** (cred capture, session-cookie theft, OTP relay, 2FA bypass, session hijack).
- **Targets: KINGNET's OWN bundled, realistic lab services** (e.g. `KingMail`, `KingBank`) — never real external sites.
- **The proxy is hard-constrained to the bundled lab targets** (fixed allowlist); lab domains resolve ONLY inside the lab network and are non-routable outside. There is **no** feature to point it at an arbitrary real site. This is what makes it legitimate, publishable, and harmless.

## What "real, not toy" means here
- Login pages served through the AiTM proxy, pixel-accurate to the lab target.
- Genuine session tokens (HttpOnly/Secure cookies / JWTs) issued by the lab services; captured and **replayed to prove full session hijack**.
- A live OTP/2FA step the proxy relays in real time → shows why TOTP/SMS 2FA does NOT stop AiTM.
- Lab DNS + an internal CA → students see real-looking domains and a valid padlock, inside the lab.
- A built-in DEFENSE demo: a passkey/FIDO2 lab service that KINGNET **cannot** phish — proving phishing-resistant MFA defeats this attack.

## Architecture (Docker Compose — one command, fully isolated)
- `kingnet-proxy` — the AiTM reverse proxy: captures creds, relays OTP, steals session cookie. Constrained to lab targets.
- `lab-targets` — `KingMail`, `KingBank` (real auth + sessions + OTP); one target passkey-enabled for the defense demo.
- `lab-dns` — resolves `*.kingnet.lab` to the proxy; lab-only, non-routable.
- `lab-ca` — internal CA issuing certs for the lab domains (valid padlock in-lab).
- `attacker-console` — web dashboard: captured creds/cookies/sessions + one-click replay/hijack.
- `lessons` — guided attack + defense walkthroughs and an explainer UI (also hosted on kasspar.com).

## Proposed stack (adjustable)
- Proxy: **Python** (custom aiohttp reverse proxy or an `mitmproxy` addon) — readable and hackable for teaching.
- Lab apps + attacker console: **Python** (FastAPI/Flask) + simple HTML/JS.
- Orchestration: **Docker Compose**. DNS: dnsmasq/CoreDNS. CA: internal (mkcert-style).

## Roadmap (phased)
- **Phase 0:** this design + repo scaffold + README with the lab-only/educational framing + license.
- **Phase 1 (MVP):** one full AiTM scenario end-to-end — `KingMail` login + OTP → KINGNET captures creds + session cookie → attacker console shows a working session hijack. `docker compose up` and it just works.
- **Phase 2 — ✅ done:** the defense half — passkey-enabled target that resists KINGNET; detection signals (new device / impossible travel / token reuse); guided lessons.
- **Phase 3:** more scenarios (KingBank, OAuth consent phishing, cookie-theft variants), polish, publish lessons on kasspar.com.

## Guardrails (enforced in code, not just docs)
- Target allowlist — proxy only serves the bundled lab services.
- Lab-only DNS — domains are non-resolvable / non-routable outside the lab.
- Prominent "LAB ONLY — educational" notices in UI, README, and an educational-use license.
- No mechanism to add arbitrary real targets.

## Open questions for the user
1. Confirm the stack (Python-based, Docker Compose) — or a preference (e.g. Go proxy)?
2. First scenario to nail in the MVP: email login + OTP (`KingMail`) — good starting target? 
3. Green light to scaffold Phase 1?
