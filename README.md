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
- **Targets are KINGNET's own bundled lab services** (`KingMail`, with `KingBank` and a passkey target coming) — never real external sites.
- **The proxy is hard-constrained in code.** On startup it refuses any upstream that isn't a loopback / private / `*.lab` host (`proxy/app.py` → `_assert_lab_only`). There is deliberately **no** feature to add an arbitrary real target.
- Everything binds to `127.0.0.1` only and runs on an isolated Docker network — it is never exposed to your LAN or the internet.

## Components

| Service | What it is |
|---|---|
| `proxy/` | The AiTM reverse proxy — captures creds, relays OTP, steals the session cookie, forwards everything so the victim notices nothing. Lab-constrained. |
| `targets/kingmail/` | A realistic lab webmail: real password login, real TOTP 2FA, real signed session cookie. Also raises **detection signals** (new device / impossible travel / token reuse) when a stolen cookie is replayed — see `/security`. **Not** a real mail service. |
| `targets/kingvault/` | **The defense demo.** A passkey-protected (WebAuthn/FIDO2) lab portal the same proxy **cannot** phish, because the assertion is bound to the origin the browser is on. The origin-binding check is in `webauthn_core.py` → `verify_assertion()`. |
| `console/` | The attacker console — shows captured creds / codes / cookies live and does one-click session hijack by replaying the stolen cookie. Also shows *why* a passkey capture is useless. |
| `scripts/local_test.sh` | Docker-free runner: drives the full KingMail attack chain **and the detection signals** end-to-end, asserting every stage. |
| `scripts/passkey_test.sh` | Docker-free proof that the passkey target resists the same proxy: honest login succeeds, the relayed assertion is rejected on origin mismatch. |
| `lessons/` | Guided walkthroughs (attack → detection → passkeys), also the basis for the kasspar.com write-ups. |

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
| http://localhost:8444/login | **Passkey attack** — the same proxy aimed at KingVault (it fails) |
| http://localhost:8082/login | **KingVault** — the passkey portal, reached directly (the real origin) |

Walk it yourself: log in at `:8443` as `victim@kingmail.lab` / `Summer2026!`, enter the code from
`:8081/phone`, and you'll reach the inbox. Now look at `:9000` — your password, your code and your
session cookie are all captured, and one click opens your mailbox *from the attacker side* with no
credentials at all.

### Option B — No Docker (venv)

```bash
python3 -m venv .venv
.venv/bin/pip install -r proxy/requirements.txt -r console/requirements.txt \
  -r targets/kingmail/requirements.txt -r targets/kingvault/requirements.txt
./scripts/local_test.sh       # KingMail: full attack chain + detection, asserted
./scripts/passkey_test.sh     # KingVault: proves the passkey defeats the same proxy
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
- **Phase 3 — next:** a browser-driven WebAuthn UI for KingVault, more scenarios (`KingBank`, OAuth consent phishing, cookie-theft variants), and publishing the lessons on kasspar.com.

## License

[KINGNET Educational License](LICENSE) — lab-only, authorized training use.
