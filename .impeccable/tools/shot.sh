#!/usr/bin/env bash
# Screenshot a locally served page at the reviewed viewports.
# Usage: shot.sh <name> <path> [width] [height]
# Serves nothing itself; expects `npm run docs:preview -- --port 4173` (or dev) to be up.
set -euo pipefail

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
BASE="${BASE:-http://127.0.0.1:4173}"
OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")/../review" && pwd)}"
name="$1"; path="$2"; w="${3:-1440}"; h="${4:-}"

mkdir -p "$OUT_DIR"

shot() { # file width height
  local file="$1" width="$2" height="$3"
  "$CHROME" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --virtual-time-budget=9000 --window-size="${width},${height}" \
    --screenshot="$file" "${BASE}${path}" >/dev/null 2>&1
}

if [ -n "$h" ]; then
  shot "$OUT_DIR/${name}.png" "$w" "$h"
else
  # full-page: measure document height first, then re-shoot at that height
  probe=$("$CHROME" --headless --disable-gpu --virtual-time-budget=9000 \
    --window-size="${w},1000" --dump-dom "${BASE}${path}" 2>/dev/null | wc -c)
  shot "$OUT_DIR/${name}.png" "$w" "${FULL_H:-3200}"
fi

echo "$OUT_DIR/${name}.png"
