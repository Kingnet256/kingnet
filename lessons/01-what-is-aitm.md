# 1 · What AiTM phishing really is

**Adversary-in-the-Middle (AiTM)** phishing puts the attacker's server *between* you and
the real site, as a live reverse proxy. The page you see is the real site's HTML, relayed
in real time. You type your password — it's relayed to the real site. The real site asks
for your 2FA code — that's relayed to you, you type it, it's relayed back. Everything works,
you reach your inbox, nothing looks wrong.

But while all that flows through the attacker's proxy, it records:

- your **password**,
- the **one-time code** (used once, in real time — so having a code didn't help), and
- most importantly, the **session cookie** the real site issues *after* you pass 2FA.

That cookie is proof you already authenticated. The attacker copies it into their own
browser and is inside your account — **no password prompt, no 2FA prompt**. This is how
real campaigns bypass SMS and authenticator-app 2FA today.

KINGNET lets you watch this happen against a realistic lab mailbox (**KingMail**), then
shows the two things that actually help: **detecting** the stolen-cookie replay, and
**preventing** the whole attack with passkeys (**KingVault**).

→ Next: [Run the attack](02-run-the-attack.md)
