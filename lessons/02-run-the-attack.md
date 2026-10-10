# 2 · Run the attack (KingMail)

## Start the lab
```bash
docker compose up --build        # or, without Docker: ./scripts/local_test.sh
```

Three roles, three URLs (all bound to localhost only):

| URL | Who |
|---|---|
| http://localhost:8443/login | **You, the victim** — the proxied "phishing" login (KINGNET in the middle) |
| http://localhost:8081/phone | **Your authenticator** — shows the current 6-digit code |
| http://localhost:9000/ | **The attacker console** |

## Play the victim
1. Go to the phishing login at **:8443** and sign in:
   `victim@kingmail.lab` / `Summer2026!`
2. It asks for a 2FA code. Read the current code from **:8081/phone** and enter it.
3. You land in the inbox. From your point of view, a totally normal login.

## Now look at the attacker console (:9000)
Everything you just did is captured in real time:
- ✔ credentials — `victim@kingmail.lab / Summer2026!`
- ✔ 2FA code (relayed)
- ✔ **session cookie — STOLEN**

Click **🎭 Hijack this session**. The console replays the stolen cookie and opens *your*
mailbox — with no password and no 2FA. That is account takeover.

> The scripted version of this exact flow, with assertions, is `./scripts/local_test.sh`.

→ Next: [Why 2FA didn't save you](03-why-2fa-fails.md)
