# KINGNET — Lab-Contained AiTM / Phishing Education Range

> ### ⚠️ LAB ONLY — FOR SECURITY EDUCATION
> KINGNET demonstrates a **real** adversary-in-the-middle (AiTM) phishing attack — credential
> capture, live 2FA relay, session-cookie theft and account takeover — against its **own
> bundled, isolated lab services**. It is built so it **cannot** be pointed at a real site
> (the proxy refuses any non-lab target at startup). Use it to learn how these attacks work
> and how to stop them. Do not use it against anyone or anything you don't own and have
> written authorization to test. See [LICENSE](LICENSE).

KINGNET is a hands-on cyber range. Inside an isolated lab you watch the *actual* attack chain
that defeats SMS/TOTP 2FA play out end-to-end — then you learn the defense that beats it
(phishing-resistant MFA / passkeys). Nothing is faked or dumbed down; only the **targets** are
contained.

---

## Why this exists

"Turn on 2FA" is good advice that stops password reuse and simple phishing — but modern AiTM
phishing **relays your login in real time** and steals the *session cookie the server issues
after you pass 2FA*. The attacker replays that cookie and is inside your account with no
password and no second factor. KINGNET lets students **see that happen** against a realistic
mailbox, so the lesson sticks — and then shows why passkeys/FIDO2 make the same attack fail.

## The attack chain (what you'll watch happen)

```
  Victim ──▶  KINGNET proxy (the "phishing link")  ──▶  KingMail (lab target)
                    │  captures password
                    │  relays the live TOTP  ── defeats SMS/TOTP 2FA
                    │  steals the post-2FA session cookie  ◀── the real prize
                    ▼
            Attacker console  ──▶  replays the stolen cookie  ──▶  victim's inbox
                                   (no password, no 2FA = account takeover)
```

## The safety boundary (this is the whole point)

- **Techniques are real and fully functional** — credential capture, live OTP relay, session-cookie theft, session hijack.
- **Targets are KINGNET's own bundled lab services** (`KingMail`, `KingBank`, and the passkey-protected `KingVault`) — never real external sites.
- **The proxy is hard-constrained in code.** On startup it refuses any upstream that isn't a loopback / private / `*.lab` host (`proxy/app.py` → `_assert_lab_only`). There is deliberately **no** feature to add an arbitrary real target.
- Everything binds to `127.0.0.1` only and runs on an isolated Docker network — it is never exposed to your LAN or the internet.

## Components

| Service | What it is |
|---|---|
| `proxy/` | The AiTM reverse proxy — captures creds, relays OTP, steals the session cookie, forwards everything so the victim notices nothing. Lab-constrained. |
| `targets/kingmail/` | A realistic lab webmail: real password login, real TOTP 2FA, real signed session cookie. Raises **detection signals** (new device / impossible travel / token reuse) on cookie replay (`/security`), and doubles as an **OAuth2 identity + resource server** (`/oauth/authorize`, `/oauth/token`, `/api/messages`, `/oauth/grants`) for the consent-phishing scenario. **Not** a real mail service. |
| `targets/kingbank/` | A lab **online bank**: password + TOTP login, a real balance, payees and transfers. Phished via the same proxy → a stolen session **drains the account**. Has fraud **detection** (`/security`) and a **step-up** policy (`/admin/policy`). **Not** a real bank. |
| `oauth-app/` | **Mail Backup Pro** — the attacker's OAuth app for the consent-phishing scenario. It never sees a password; it lures the victim to KingMail's real consent screen and, on *Allow*, swaps the code for a mailbox token. |
| `targets/kingvault/` | **The defense demo.** A passkey-protected (WebAuthn/FIDO2) lab portal the same proxy **cannot** phish, because the assertion is bound to the origin the browser is on. The origin-binding check is in `webauthn_core.py` → `verify_assertion()`. |
| `console/` | The attacker console — shows captured creds / codes / cookies live and does one-click session hijack by replaying the stolen cookie. Also shows *why* a passkey capture is useless. |
| `scripts/local_test.sh` | Docker-free runner: drives the full KingMail attack chain **and the detection signals** end-to-end, asserting every stage. |
| `scripts/passkey_test.sh` | Docker-free proof that the passkey target resists the same proxy: honest login succeeds, the relayed assertion is rejected on origin mismatch. |
| `scripts/oauth_test.sh` | Docker-free proof of the OAuth consent-phishing scenario: no creds phished, then visibility / revoke / policy-block defenses. |
| `scripts/bank_test.sh` | Docker-free proof of the KingBank scenario: phish → stolen session drains the account → detection + step-up catch/stop it. |
| `scripts/cookie_theft_test.sh` | Docker-free proof of the cookie-theft variants: stored XSS (HttpOnly + encoding defend) and an infostealer (device-bound sessions defend). Needs `node`. |
| `lessons/` | Guided walkthroughs (attack → detection → passkeys → consent phishing), also the basis for the kasspar.com write-ups. |

## Quick start

### Option A — Docker (recommended, fully isolated)

```bash
docker compose up --build
```

Then open:

| URL | Role |
|---|---|
| http://localhost:8443/login | **Victim** — the proxied "phishing" login (this is KINGNET in the middle) |
| http://localhost:8081/phone | **Victim's authenticator** — shows the current 6-digit code to type |
| http://localhost:8081/security | **Defender** — detection alerts once the stolen cookie is replayed |
| http://localhost:9000/ | **Attacker console** — watch captures land, then click *Hijack* |
| http://localhost:8082/login | **KingVault** — the passkey portal (real origin). Click *Sign in with passkey* to enroll + log in with a genuine browser passkey. |
| http://localhost:8444/login | **Passkey attack** — the same proxy aimed at KingVault; it warns you're on the wrong origin and the sign-in is rejected. |
| http://localhost:8070/ | **Mail Backup Pro** — the attacker's OAuth app. *Connect* sends you to KingMail's real consent screen (consent-phishing lesson). |
| http://localhost:8081/oauth/grants | **Defender** — third-party apps with mailbox access; revoke here. |
| http://localhost:8446/login | **Banking phish** — the proxy aimed at KingBank (`victim@kingbank.lab` / `Autumn2026!`). |
| http://localhost:8083/phone | **KingBank authenticator** — the transaction/login code. `/security` shows fraud alerts. |

Walk it yourself: log in at `:8443` as `victim@kingmail.lab` / `Summer2026!`, enter the code from
`:8081/phone`, and you'll reach the inbox. Now look at `:9000` — your password, your code and your
session cookie are all captured, and one click opens your mailbox *from the attacker side* with no
credentials at all.

### Option B — No Docker (venv)

```bash
python3 -m venv .venv
.venv/bin/pip install -r proxy/requirements.txt -r console/requirements.txt \
  -r targets/kingmail/requirements.txt -r targets/kingvault/requirements.txt \
  -r targets/kingbank/requirements.txt -r oauth-app/requirements.txt \
  -r scripts/requirements-dev.txt   # last one is test-only
./scripts/local_test.sh       # KingMail: full attack chain + detection, asserted
./scripts/passkey_test.sh     # KingVault: proves the passkey defeats the same proxy
./scripts/oauth_test.sh       # OAuth consent phishing + defenses
./scripts/bank_test.sh        # KingBank: stolen session drains the account; defenses stop it
./scripts/cookie_theft_test.sh # XSS + infostealer cookie theft; HttpOnly / encoding / DBSC defend
```

Both scripts are the project's smoke tests — they exit non-zero if any stage breaks.

## The lab victim account

| Field | Value |
|---|---|
| Email | `victim@kingmail.lab` |
| Password | `Summer2026!` |
| TOTP secret | `JBSWY3DPEHPK3PXP` (fixed so `/phone` can show you the live code) |

## Roadmap

- **Phase 0 — ✅ done:** design, scaffold, lab-only framing, license.
- **Phase 1 — ✅ done:** full KingMail AiTM scenario end-to-end (login + OTP → capture + session hijack), verified by `scripts/local_test.sh`.
- **Phase 2 — ✅ done:** the defense half — a passkey/FIDO2 target (`KingVault`) KINGNET **cannot** phish (verified by `scripts/passkey_test.sh`), detection signals on KingMail (new device / impossible travel / token reuse, at `/security`), and guided `lessons/`.
- **Phase 3 — in progress:** ✅ real browser-driven WebAuthn for KingVault; ✅ **OAuth consent-phishing scenario** (`oauth-app/` + KingMail as IdP, with visibility / revoke / policy-block defenses); ✅ **KingBank** scenario (AiTM → stolen session drains the account, with detection + step-up defenses); ✅ **cookie-theft variants** (stored XSS + infostealer, with HttpOnly / output-encoding / device-bound-session defenses); ✅ **lessons published** — `lessons/build_site.py` renders them to a static site, live at `lab.kasspar.com`. **Phase 3 complete.**

## License

[KINGNET Educational License](LICENSE) — lab-only, authorized training use.
