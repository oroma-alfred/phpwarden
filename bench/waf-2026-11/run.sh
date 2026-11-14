#!/bin/sh
# Rerun the WAF-rule benchmark. Builds a benign request corpus and a set of
# exploit request shapes (both generated, nothing is sent anywhere), then
# checks them against `rules --replay` and the generated nginx/ModSecurity
# rules. Needs git and python3; network only to fetch WordPress, whose file
# list supplies the realistic WordPress paths. Work files go to $BENCH_DATA
# (default: a temp dir).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
W="${BENCH_DATA:-$(mktemp -d)}"; mkdir -p "$W"
if [ ! -d "$W/wordpress/.git" ]; then
  git init -q "$W/wordpress" && git -C "$W/wordpress" remote add origin https://github.com/WordPress/WordPress.git
  git -C "$W/wordpress" fetch -q --depth 1 origin db96f5eaa77a8d3e8eec8923a518fa2326f0d46a   # 7.1.4
  git -C "$W/wordpress" -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
python3 -I "$HERE/corpus.py" "$W/wordpress" "$W/out"
python3 -I "$HERE/evaluate.py" "$REPO" "$W/out"
echo "work dir: $W (benign.log, attacks.tsv, false-positives.tsv in out/)"
