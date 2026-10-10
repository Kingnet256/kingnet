# 5 · Passkeys defeat AiTM (KingVault)

**KingVault** is the same kind of lab service, but it logs in with a **passkey**
(WebAuthn/FIDO2) instead of a password + code. Point the *same* KINGNET proxy at it and
the attack that owned KingMail simply fails.

## See it
```bash
./scripts/passkey_test.sh
```
It enrolls a passkey on the real KingVault origin, logs in honestly (**succeeds**), then
runs the identical login **through the proxy** (**rejected, HTTP 401**), and shows the
attacker console marking the captured assertion useless.

## Why it works — origin binding
When you use a passkey, your authenticator **signs the exact origin of the page you're on**
(scheme + host + port) together with a server challenge. The signature is checked by the
real service against *its own* origin.

A phishing proxy necessarily lives at a **different origin** than the real service. So:

- Your authenticator signs the **proxy's** origin (that's the page you're actually on).
- The proxy relays that signature to the real service.
- The real service compares the signed origin to its own — they differ — and **refuses it**.

The attacker captured the assertion, but it is cryptographically bound to the phishing page
and worth nothing anywhere else. There is **no shared secret to relay**: no password, no
code, and the signature can't be reused. See `targets/kingvault/webauthn_core.py` — the
check lives in `verify_assertion()`.

## The takeaway
- Passwords + SMS/TOTP: phishable, because they're shared secrets you can be tricked into
  relaying.
- Passkeys (FIDO2/WebAuthn): **phishing-resistant**, because the proof is bound to the real
  origin and never leaves your device.

That's why moving high-value logins to passkeys — not just "turning on 2FA" — is what
actually stops AiTM.
