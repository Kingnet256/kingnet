#!/usr/bin/env bash
#
# KINGNET Phase 3 — KingBank AiTM scenario. Docker-free: launches KingBank, the attacker
# console, and a proxy aimed at the bank (stealing the kingbank_session cookie). The victim
# is phished; the attacker drains the account with the stolen session; detection flags it;
# a step-up policy refuses it. Lab-only.
#
set -uo pipefail

export KINGNET_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$KINGNET_ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

export KINGBANK_URL="http://localhost:8083"
export PROXY_ORIGIN="http://localhost:8446"
export CONSOLE_URL="http://localhost:9000"
TMP="$(mktemp -d)"
export CONSOLE_DB="$TMP/captures.db"

cleanup() {
  for p in 8083 8446 9000; do
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

say "Launching KingBank, attacker console, and an AiTM proxy aimed at the bank"
spawn kingbank targets/kingbank 8083 "KINGBANK_SECRET=bank-test"
spawn console  console          9000 "CONSOLE_DB=$CONSOLE_DB"
spawn bankproxy proxy           8446 "TARGET_URL=$KINGBANK_URL" "PROXY_PUBLIC_URL=$PROXY_ORIGIN" \
      "CONSOLE_URL=$CONSOLE_URL" "SESSION_COOKIE_NAME=kingbank_session"

wait_up "$KINGBANK_URL" "KingBank"        || { tail -n 20 "$TMP/kingbank.log"; exit 1; }
wait_up "$CONSOLE_URL"  "Attacker console" || exit 1
wait_up "$PROXY_ORIGIN" "AiTM proxy"      || { tail -n 20 "$TMP/bankproxy.log"; exit 1; }

"$PY" "$KINGNET_ROOT/scripts/_bank_flow.py"
rc=$?

echo
if [ "$rc" = 0 ]; then
  printf '\033[1;32m==> PASS — account drained via the stolen session; detection + step-up catch/stop it.\033[0m\n'
else
  printf '\033[1;31m==> FAIL. Service logs:\033[0m\n'
  for l in kingbank bankproxy console; do echo "--- $l.log ---"; tail -n 20 "$TMP/$l.log" 2>/dev/null; done
fi
exit $rc
