#!/usr/bin/env bash
#
# KINGNET Phase 2 — proof that the passkey target (KingVault) defeats the SAME AiTM
# proxy that fully owns KingMail. Docker-free: launches KingVault, the attacker
# console, and a proxy instance pointed at KingVault, then runs the passkey ceremony
# honestly (succeeds) and via the proxy (must fail on origin binding). Lab-only.
#
set -uo pipefail

export KINGNET_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$KINGNET_ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

export KV_ORIGIN="http://localhost:8082"
export PROXY_ORIGIN="http://localhost:8445"
export CONSOLE_URL="http://localhost:9000"

TMP="$(mktemp -d)"
export CONSOLE_DB="$TMP/captures.db"

cleanup() {
  # Kill by exact host:port match — deterministic teardown of this lab's own servers.
  for p in 8082 8445 9000; do
    pkill -9 -f "uvicorn app:app --host 127.0.0.1 --port $p" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

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

say "Launching KingVault (passkey target), attacker console, and an AiTM proxy aimed at it"
spawn kingvault targets/kingvault 8082 "KINGVAULT_ORIGIN=$KV_ORIGIN" "KINGVAULT_RP_ID=localhost" "KINGVAULT_SECRET=kv-test"
spawn console   console          9000 "CONSOLE_DB=$CONSOLE_DB"
spawn kvproxy   proxy            8445 "TARGET_URL=$KV_ORIGIN" "PROXY_PUBLIC_URL=$PROXY_ORIGIN" "CONSOLE_URL=$CONSOLE_URL"

wait_up "$KV_ORIGIN"      "KingVault target" || { tail -n 20 "$TMP/kingvault.log"; exit 1; }
wait_up "$CONSOLE_URL"    "Attacker console" || exit 1
wait_up "$PROXY_ORIGIN"   "AiTM proxy"       || { tail -n 20 "$TMP/kvproxy.log"; exit 1; }

"$PY" "$KINGNET_ROOT/scripts/_passkey_ceremony.py"
rc=$?

echo
if [ "$rc" = 0 ]; then
  printf '\033[1;32m==> PASS — the passkey target resisted the AiTM proxy. Phishing-resistant MFA works.\033[0m\n'
else
  printf '\033[1;31m==> FAIL. Service logs:\033[0m\n'
  for l in kingvault kvproxy console; do echo "--- $l.log ---"; tail -n 20 "$TMP/$l.log" 2>/dev/null; done
fi
exit $rc
