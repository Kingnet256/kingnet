# 7 · Banking AiTM — account takeover to money moved

The mail attack was bad; the bank attack is worse, because the prize is cash. **KingBank**
is a lab online bank — real login + 2FA, a real balance, real transfers. Point the same
KINGNET proxy at it and the chain is identical to KingMail: phish the login, relay the 2FA,
**steal the session cookie**. The difference is what the attacker does next.

## Run it
```bash
./scripts/bank_test.sh         # scripted, asserted end-to-end
```
Or by hand with `docker compose up`:
1. As the victim, sign in at the phishing proxy **http://localhost:8446/login**
   (`victim@kingbank.lab` / `Autumn2026!`, code from **http://localhost:8083/phone**).
2. Watch the attacker console (**http://localhost:9000**) capture the password, the code,
   and the **kingbank_session** cookie.
3. As the attacker, replay that cookie from another machine and `POST /pay` to a mule
   account — the balance **drains** (R75,000 → R15,000 in the script). To this bank, holding
   the session *is* authority, so no password or fresh code is needed to move money.

## Why the session is enough
Many banking actions only check that you have a valid session. An AiTM attacker who stole
the post-2FA session cookie has exactly that. The second factor you passed at login did
nothing to protect the *transaction*.

## What limits the damage
- **Detection** — KingBank fingerprints your session and flags a transfer from a **new
  device / impossible travel / to a new payee** on **/security**. Banks use exactly these
  signals to freeze suspicious payments.
- **Per-transaction step-up** — require a fresh authorization for payments
  (`POST /admin/policy {"require_step_up": true}`). Now the stolen session alone can't pay;
  the thief would need the victim's authenticator for every transfer. The script shows the
  same fraud getting refused once this is on.
- **Bind the transaction, and use phishing-resistant auth** — the real fix combines
  [passkeys](05-passkeys-defeat-aitm.md) (so the session is never stolen) with transaction
  signing that shows and binds the exact payee + amount being approved (so a man-in-the-middle
  can't alter where the money goes). What you approve should be what you see.

## The takeaway
A stolen session is money in a bank. "We have 2FA" protects the *login*, not the *payment*.
Protect the payment: anomaly detection, step-up on risky actions, transaction binding, and
phishing-resistant sign-in.
