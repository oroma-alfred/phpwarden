#!/bin/sh
# Rerun the probe correctness benchmark. Starts seven fixture sites on 127.0.0.1,
# probes each, and compares the findings with what was planted. Needs python3
# only; makes no request to any other host.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
PHPWARDEN_FREE_FEED_URL=off python3 "$HERE/bench.py" "$REPO"
