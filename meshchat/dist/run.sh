#!/usr/bin/env sh
# meshchat bundle launcher. Keeps shared libraries relative to this script.
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -d "$DIR/lib" ]; then
  LD_LIBRARY_PATH="$DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export LD_LIBRARY_PATH
fi

if [ "$#" -eq 0 ]; then
  NAME=$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9_-' | cut -c1-24)
  if [ -z "$NAME" ]; then NAME=MeshUser; fi
  exec "$DIR/meshchat" --name "$NAME" --port 0
fi

exec "$DIR/meshchat" "$@"
