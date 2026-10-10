# 3 · Why SMS/TOTP 2FA doesn't stop AiTM

2FA with an SMS or authenticator code defends against **stolen or reused passwords**: even
with your password, an attacker can't produce the current code. That's real, keep it on.

What it does **not** defend against is a **live relay**. In an AiTM attack the attacker
isn't logging in later from their own machine — they're relaying *your* login as it happens.
So:

- The code is only needed **once, right now** — and you supplied it, through the proxy.
- After you pass 2FA, the server issues a **session cookie**. From then on, that cookie —
  not your password or code — is what proves who you are. Steal the cookie and you *are*
  the authenticated user.

The root problem: passwords and one-time codes are **shared secrets**. Anything you can
type into a convincing page, you can type into a convincing *proxy* of that page, and the
attacker gets a copy. The session cookie is just the most valuable secret of all because it
represents an already-completed login.

Two things actually change the game:
1. **Detect** the stolen-cookie replay → [Lesson 4](04-detection.md).
2. **Stop the credential being phishable at all** with passkeys → [Lesson 5](05-passkeys-defeat-aitm.md).
