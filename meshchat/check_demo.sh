#!/usr/bin/env bash
set -uo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_ARG=""
PEERS=""

usage() {
  cat <<'EOF'
Usage: ./check_demo.sh [--binary PATH] [--peers ip:port,...]

Verifies the pre-demo environment:
  - binary runs
  - UDP ports 9001-9004, 9999, and the check ports are free
  - two loopback instances discover each other over broadcast
  - at least one --peers seed responds, if supplied
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary|--bin)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 1; }
      BIN_ARG="$2"
      shift 2
      ;;
    --peers)
      [[ $# -ge 2 ]] || { echo "missing value for --peers" >&2; exit 1; }
      PEERS="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -n "$BIN_ARG" ]]; then
  if [[ "$BIN_ARG" != /* ]]; then
    BIN="$(pwd)/$BIN_ARG"
  else
    BIN="$BIN_ARG"
  fi
fi
cd "$SELF_DIR" || exit 1
if [[ -z "${BIN:-}" ]]; then
  for candidate in ./build/meshchat ../build/root/meshchat ../build/meshchat; do
    if [[ -x "$candidate" ]]; then BIN="$(pwd)/$candidate"; break; fi
  done
fi
if [[ -z "${BIN:-}" || ! -x "$BIN" ]]; then
  echo "NOT READY: meshchat binary not found or not executable"
  exit 1
fi

TMP="$(mktemp -d 2>/dev/null || echo "/tmp/meshchat-check-$$")"
mkdir -p "$TMP"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lun 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lun 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
  else
    return 1
  fi
}

if ! "$BIN" --version >"$TMP/version.log" 2>&1; then
  echo "NOT READY: binary does not run (Smart App Control or a missing runtime library may be blocking it)"
  cat "$TMP/version.log" 2>/dev/null || true
  exit 1
fi

for port in 9001 9002 9003 9004 9999 19190 19191 19192; do
  if port_in_use "$port"; then
    echo "NOT READY: UDP port $port is already in use (stop a previous demo or check what owns it)"
    exit 1
  fi
done

# Two loopback instances prove that broadcast bind and discovery work on this host.
"$BIN" --name CheckA --port 19190 --no-color --run-for 8 >"$TMP/a.log" 2>&1 &
PIDS+=("$!")
"$BIN" --name CheckB --port 19191 --no-color --run-for 8 >"$TMP/b.log" 2>&1 &
PIDS+=("$!")
wait "${PIDS[0]}"; A_STATUS=$?
wait "${PIDS[1]}"; B_STATUS=$?
PIDS=()
if [[ $A_STATUS -ne 0 || $B_STATUS -ne 0 ]]; then
  echo "NOT READY: the loopback discovery pair exited unexpectedly"
  echo "--- CheckA ---"; tail -20 "$TMP/a.log" 2>/dev/null || true
  echo "--- CheckB ---"; tail -20 "$TMP/b.log" 2>/dev/null || true
  exit 1
fi
if ! grep -q "Online:.*CheckB" "$TMP/a.log" || ! grep -q "Online:.*CheckA" "$TMP/b.log"; then
  echo "NOT READY: UDP broadcast discovery failed between two loopback instances"
  echo "Check the firewall and do not run this check while a demo is using port 9999."
  exit 1
fi

if [[ -n "$PEERS" ]]; then
  "$BIN" --name CheckSeed --port 19192 --no-color --no-broadcast \
    --peers "$PEERS" --run-for 8 >"$TMP/seed.log" 2>&1 &
  PIDS+=("$!")
  wait "${PIDS[0]}"; SEED_STATUS=$?
  PIDS=()
  if [[ $SEED_STATUS -ne 0 ]]; then
    echo "NOT READY: the --peers reachability probe exited unexpectedly"
    tail -20 "$TMP/seed.log" 2>/dev/null || true
    exit 1
  fi
  if ! grep -q "Online:" "$TMP/seed.log"; then
    echo "NOT READY: no --peers seed responded (check the addresses, firewall, and that the other nodes are running)"
    exit 1
  fi
fi

if [[ -t 1 ]]; then
  printf '\033[32mREADY\033[0m\n'
else
  echo "READY"
fi
exit 0
