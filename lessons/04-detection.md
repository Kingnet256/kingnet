# 4 · Catching the replay (detection)

2FA didn't stop the theft — but the attacker now has to *use* the stolen cookie, and that
use looks different from you. KingMail fingerprints every session when it's issued and
raises alerts when the same cookie appears from a new fingerprint.

## See it
After you hijack the session in [Lesson 2](02-run-the-attack.md), open:

**http://localhost:8081/security**

You'll see the replay flagged with three classic signals:

- **New device** — the cookie was issued to your browser, but is now used from the
  attacker's tooling (a different User-Agent).
- **Impossible travel** — issued in one location, used seconds later from another.
  *(In the lab, location is supplied by an `X-Lab-Geo` header standing in for GeoIP.)*
- **Session token reuse** — the same session cookie is live from two different clients
  at once.

A real service reacting to these would **kill the session**, force a fresh login, or
require step-up re-authentication — which is where a phishing-resistant method matters.

Detection is a safety net, not a cure: the attacker still got in first. To remove the
prize entirely, you need a credential that **can't be phished**.

→ Next: [Passkeys defeat AiTM](05-passkeys-defeat-aitm.md)
