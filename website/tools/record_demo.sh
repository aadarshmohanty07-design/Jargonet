#!/usr/bin/env bash
set -euo pipefail

BIN="${1:?usage: record_demo.sh <meshchat-binary> <output.cast>}"
OUT="${2:?usage: record_demo.sh <meshchat-binary> <output.cast>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
SESSION="meshchat-demo"
ASCIINEMA="${ASCIINEMA:-asciinema}"

if ! command -v "$ASCIINEMA" >/dev/null 2>&1; then
  echo "asciinema is required (pip install asciinema)" >&2
  exit 1
fi
if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required" >&2
  exit 1
fi
if [[ ! -x "$BIN" ]]; then
  echo "meshchat binary is not executable: $BIN" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
tmux kill-session -t "$SESSION" 2>/dev/null || true
trap 'tmux kill-session -t "$SESSION" 2>/dev/null || true' EXIT

COLUMNS=120 LINES=40 bash "$ROOT/meshchat/run_demo.sh" --bin "$BIN" --no-attach
sleep 5

send() {
  local target="$1" text="$2"
  tmux send-keys -t "$target" -l "$text"
  tmux send-keys -t "$target" Enter
}

COLUMNS=120 LINES=40 "$ASCIINEMA" rec --overwrite \
  --command "tmux attach -t $SESSION" "$OUT" &
REC=$!
sleep 2

send "$SESSION:0.0" "/peers"
sleep 3
send "$SESSION:0.0" "/send Bob hi"
sleep 3
send "$SESSION:0.0" "/send Bob --relays 2 hello through the mesh"
sleep 5
send "$SESSION:0.2" "/quit"
sleep 3
send "$SESSION:0.0" "/peers"
sleep 3
send "$SESSION:0.0" "/send Bob --relays 1 still works"
sleep 4

tmux detach-client -s "$SESSION" 2>/dev/null || true
wait "$REC" || true

if [[ ! -s "$OUT" ]]; then
  echo "recording did not produce a cast file" >&2
  exit 1
fi
echo "recorded $(wc -c < "$OUT") bytes to $OUT"
