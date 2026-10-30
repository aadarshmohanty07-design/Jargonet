#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

BIN="${1:-./build/meshchat}"
if [[ ! -x "$BIN" ]]; then
  echo "meshchat binary not found or not executable: $BIN" >&2
  echo "Build it with: cmake -S . -B build -G Ninja && cmake --build build" >&2
  exit 1
fi
if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required. Start four terminals with:" >&2
  echo "  $BIN --name Alice --port 9001" >&2
  echo "  $BIN --name Bob --port 9002" >&2
  echo "  $BIN --name Relay1 --port 9003" >&2
  echo "  $BIN --name Relay2 --port 9004" >&2
  exit 1
fi

SESSION="meshchat-demo"
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -n Alice "$BIN --name Alice --port 9001"
tmux split-window -h -t "$SESSION" "$BIN --name Bob --port 9002"
tmux split-window -v -t "$SESSION" "$BIN --name Relay1 --port 9003"
tmux split-window -v -t "$SESSION" "$BIN --name Relay2 --port 9004"
tmux select-layout -t "$SESSION" tiled
tmux set-option -t "$SESSION" remain-on-exit on
tmux attach -t "$SESSION"
