#!/usr/bin/env bash
#
# KINGNET Phase 3 — cookie-theft variants (no AiTM proxy): stored XSS and an infostealer,
# each with its defense (HttpOnly + output encoding; device-bound sessions). Docker-free:
# launches KingMail + the attacker console (drop server) and runs both variants. Needs node.
# Lab-only.
#
set -uo pipefail

export KINGNET_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$KINGNET_ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

export KINGMAIL_URL="http://localhost:8081"
export CONSOLE_URL="http://localhost:9000"
TMP="$(mktemp -d)"
export CONSOLE_DB="$TMP/captures.db"

cleanup() {
  for p in 8081 9000; do
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

command -v node >/dev/null 2>&1 || { echo "node is required for the XSS browser harness"; exit 1; }

say "Launching KingMail and the attacker console (drop server)"
spawn kingmail targets/kingmail 8081 "KINGMAIL_SECRET=cookie-test"
spawn console  console          9000 "CONSOLE_DB=$CONSOLE_DB"
wait_up "$KINGMAIL_URL" "KingMail"         || { tail -n 20 "$TMP/kingmail.log"; exit 1; }
wait_up "$CONSOLE_URL"  "Attacker console" || exit 1

"$PY" "$KINGNET_ROOT/scripts/_cookie_theft.py"
rc=$?

echo
if [ "$rc" = 0 ]; then
  printf '\033[1;32m==> PASS — both cookie-theft variants demonstrated, both defenses hold.\033[0m\n'
else
  printf '\033[1;31m==> FAIL. Service logs:\033[0m\n'
  for l in kingmail console; do echo "--- $l.log ---"; tail -n 20 "$TMP/$l.log" 2>/dev/null; done
fi
exit $rc
