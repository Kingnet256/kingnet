# 6 · OAuth consent phishing (no password needed)

Every attack so far tried to get your *credentials*. This one doesn't bother. In an
**illicit consent grant**, the attacker registers an app and simply asks you to **grant it
access** to your account. You sign in to the **real** service (real password, real 2FA —
never phished), see a normal consent screen, click **Allow**, and the attacker's app walks
away with a token that can read your mail. No AiTM proxy, nothing stolen on the wire — you
*gave* it access.

## Run it
```bash
docker compose up --build        # or, scripted: ./scripts/oauth_test.sh
```
As the victim:
1. Make sure you're signed in to the real KingMail (**http://localhost:8081**).
2. Open the attacker's app, **Mail Backup Pro** — **http://localhost:8070** — and click
   *Connect your KingMail*.
3. You land on KingMail's **own** consent screen (note the red *unverified* publisher). Click
   **Allow**.
4. Mail Backup Pro's console now shows an access token for your mailbox and prints your
   confidential mail — it never saw your password or a code.

## Why it works
OAuth is *meant* to let you delegate access to apps. Consent phishing abuses that: the
dangerous step isn't typing a secret, it's **clicking Allow** on a scope like
`mail.read`. MFA doesn't help — you really did authenticate. The only secret involved,
the app's token, was handed over by design.

## What stops it
- **See what has access:** KingMail lists third-party apps at **/oauth/grants** and raises a
  security alert on **/security** when a grant is made.
- **Revoke:** removing the grant kills the app's tokens immediately (try the *Remove access*
  button, then watch Mail Backup Pro lose its access).
- **Policy:** an admin can block consent to **unverified** apps outright. Toggle it
  (`POST /admin/consent-policy {"block_unverified": true}`) and the same Allow click is
  refused.

## The takeaway
Train people that "Allow this app to access your account" is a security decision, restrict
who can consent, require verified publishers, and review app grants — because no amount of
MFA stops a user from *granting* access.
