#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

BIN="${MESHCHAT_BIN:-}"
PEERS=""
NO_ATTACH=0

usage() {
  cat <<'EOF'
Usage: ./run_demo.sh [--bin PATH] [--peers ip:port,...] [--no-attach]

Starts four labeled meshchat nodes in a 2x2 tmux grid:
  Alice 9001, Bob 9002, R1 9003, R2 9004.

Pass --peers when UDP broadcast is isolated by the access point.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      [[ $# -ge 2 ]] || { echo "missing value for --bin" >&2; exit 1; }
      BIN="$2"
      shift 2
      ;;
    --peers)
      [[ $# -ge 2 ]] || { echo "missing value for --peers" >&2; exit 1; }
      PEERS="$2"
      shift 2
      ;;
    --no-attach)
      NO_ATTACH=1
      shift
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

if [[ -z "$BIN" ]]; then
  for candidate in ./build/meshchat ../build/root/meshchat ../build/meshchat; do
    if [[ -x "$candidate" ]]; then BIN="$candidate"; break; fi
  done
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  echo "meshchat binary not found or not executable." >&2
  echo "Build it with: cmake -S . -B build -G Ninja && cmake --build build" >&2
  echo "or pass --bin /path/to/meshchat." >&2
  exit 1
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required. Start four terminals manually:" >&2
  echo "  $BIN --name Alice --port 9001${PEERS:+ --peers $PEERS}" >&2
  echo "  $BIN --name Bob --port 9002${PEERS:+ --peers $PEERS}" >&2
  echo "  $BIN --name R1 --port 9003${PEERS:+ --peers $PEERS}" >&2
  echo "  $BIN --name R2 --port 9004${PEERS:+ --peers $PEERS}" >&2
  exit 1
fi

SESSION="meshchat-demo"
tmux kill-session -t "$SESSION" 2>/dev/null || true

node_command() {
  local name="$1" port="$2"
  printf 'exec %q --name %q --port %d' "$BIN" "$name" "$port"
  if [[ -n "$PEERS" ]]; then
    printf ' --peers %q' "$PEERS"
  fi
}

tmux new-session -d -s "$SESSION" -n "Alice" "$(node_command Alice 9001)"
tmux split-window -h -t "$SESSION:0.0" "$(node_command Bob 9002)"
tmux split-window -v -t "$SESSION:0.0" "$(node_command R1 9003)"
tmux split-window -v -t "$SESSION:0.1" "$(node_command R2 9004)"
tmux select-layout -t "$SESSION:0" tiled
tmux set-option -w -t "$SESSION:0" pane-border-status top
tmux set-option -w -t "$SESSION:0" pane-border-format "#{pane_title}"
tmux select-pane -t "$SESSION:0.0" -T "Alice"
tmux select-pane -t "$SESSION:0.1" -T "Bob"
tmux select-pane -t "$SESSION:0.2" -T "R1"
tmux select-pane -t "$SESSION:0.3" -T "R2"

echo "Demo ready. Alice=9001 Bob=9002 R1=9003 R2=9004. Type /peers on any node."
tmux display-message -t "$SESSION" "Demo ready. Alice=9001 Bob=9002 R1=9003 R2=9004. Type /peers on any node."
if [[ "$NO_ATTACH" == "1" ]]; then
  echo "tmux session '$SESSION' is running (not attaching)."
  exit 0
fi
tmux attach -t "$SESSION"
