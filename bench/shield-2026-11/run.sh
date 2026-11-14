#!/bin/sh
# Rerun the shield benchmark. Needs python3, php (for the agent and latency
# parts) and git (to fetch WordPress for the benign corpus, as the WAF benchmark
# does). Nothing is sent to any host other than 127.0.0.1.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
W="${BENCH_DATA:-$(mktemp -d)}"; mkdir -p "$W"
if [ ! -f "$W/out/benign.log" ]; then
  if [ ! -d "$W/wordpress/.git" ]; then
    git init -q "$W/wordpress" && git -C "$W/wordpress" remote add origin https://github.com/WordPress/WordPress.git
    git -C "$W/wordpress" fetch -q --depth 1 origin db96f5eaa77a8d3e8eec8923a518fa2326f0d46a   # 7.1.4
    git -C "$W/wordpress" -c advice.detachedHead=false checkout -q FETCH_HEAD
  fi
  python3 -I "$REPO/bench/waf-2026-11/corpus.py" "$W/wordpress" "$W/out" >/dev/null
fi
python3 -I "$HERE/bench.py" "$REPO" "$W/out/benign.log" "$W/shield"
