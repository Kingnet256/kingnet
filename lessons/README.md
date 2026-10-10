# KINGNET Lessons

Guided, hands-on walkthroughs for the KINGNET lab. Work them in order: first *become*
the attacker and succeed against a normal 2FA account, then watch the same attack get
detected, then watch it fail completely against a passkey. Everything is lab-only.

| # | Lesson | You will see |
|---|--------|--------------|
| 1 | [What AiTM phishing really is](01-what-is-aitm.md) | why "turn on 2FA" isn't the whole story |
| 2 | [Run the attack (KingMail)](02-run-the-attack.md) | capture creds, relay the OTP, steal the session, take over the account |
| 3 | [Why SMS/TOTP 2FA doesn't stop it](03-why-2fa-fails.md) | the session cookie is the real prize |
| 4 | [Catching the replay (detection)](04-detection.md) | new device / impossible travel / token reuse |
| 5 | [Passkeys defeat AiTM (KingVault)](05-passkeys-defeat-aitm.md) | the same attack fails on origin binding |
| 6 | [OAuth consent phishing](06-oauth-consent-phishing.md) | an attack that needs no password at all — and how to shut it down |
| 7 | [Banking AiTM (KingBank)](07-banking-aitm.md) | account takeover → the account gets drained, and what limits it |
| 8 | [Stealing the session without a proxy](08-cookie-theft-variants.md) | XSS vs infostealer cookie theft, HttpOnly, and device-bound sessions |

> These lessons are also the basis for the public write-ups on kasspar.com. The lab
> itself must never be pointed at a real service — see the top-level README and LICENSE.
