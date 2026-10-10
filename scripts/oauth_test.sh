#!/usr/bin/env bash
#
# KINGNET Phase 3 — OAuth consent phishing scenario. Docker-free: launches KingMail
# (identity + resource server) and the attacker's app "Mail Backup Pro", then runs the
# full illicit-consent-grant flow and the defenses. No credential is ever phished.
# Lab-only.
#
set -uo pipefail

export KINGNET_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$KINGNET_ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

export KINGMAIL_URL="http://localhost:8081"
export OAUTH_APP_URL="http://localhost:8070"
TMP="$(mktemp -d)"

cleanup() {
  for p in 8081 8070; do
    pkill -9 -f "uvicorn app:app --host 127.0.0.1 --port $p" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

spawn() { # name dir port env...
  local name="$1" dir="$2" port="$3"; shift 3
  ( cd "$KINGNET_ROOT/$dir" && env "$@" "$PY" -m uvicorn app:app --host 127.0.0.1 --port "$port" \
      >"$TMP/$name.log" 2>&1 & echo $! >"$TMP/$name.pid" )
}

wait_up() {
  local url="$1" name="$2" i
  for i in $(seq 1 60); do
    curl -fsS "$url/healthz" >/dev/null 2>&1 && { printf '   \033[1;32m✓\033[0m %s is up\n' "$name"; return 0; }
    sleep 0.25
  done
  printf '   \033[1;31m✗ %s did not come up\033[0m\n' "$name"; return 1
}

say "Launching KingMail (identity+resource server) and the attacker app Mail Backup Pro"
spawn kingmail targets/kingmail 8081 \
  "KINGMAIL_SECRET=oauth-test" "OAUTH_MAILBACKUP_REDIRECT=$OAUTH_APP_URL/callback" \
  "OAUTH_MAILBACKUP_SECRET=mailbackup-lab-secret"
spawn oauthapp oauth-app 8070 \
  "KINGMAIL_PUBLIC=$KINGMAIL_URL" "KINGMAIL_INTERNAL=$KINGMAIL_URL" "SELF_PUBLIC=$OAUTH_APP_URL" \
  "OAUTH_CLIENT_SECRET=mailbackup-lab-secret"

wait_up "$KINGMAIL_URL"  "KingMail"         || { tail -n 20 "$TMP/kingmail.log"; exit 1; }
wait_up "$OAUTH_APP_URL" "Mail Backup Pro"  || { tail -n 20 "$TMP/oauthapp.log"; exit 1; }

"$PY" "$KINGNET_ROOT/scripts/_oauth_flow.py"
rc=$?

echo
if [ "$rc" = 0 ]; then
  printf '\033[1;32m==> PASS — consent phishing works (no creds stolen), and the defenses catch/stop it.\033[0m\n'
else
  printf '\033[1;31m==> FAIL. Service logs:\033[0m\n'
  for l in kingmail oauthapp; do echo "--- $l.log ---"; tail -n 20 "$TMP/$l.log" 2>/dev/null; done
fi
exit $rc
