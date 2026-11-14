#!/bin/sh
# Rerun the code-scanner benchmark: recall on deliberately vulnerable apps
# (DVWA, Mutillidae II), findings on clean, widely used codebases (WordPress,
# Laravel, Symfony) and speed. Needs git, python3 and network access to GitHub.
# Third-party code is cloned into $BENCH_DATA (default: a temp dir), never into
# this repository. Targets are pinned by commit, so every run scans the same code.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
W="${BENCH_DATA:-$(mktemp -d)}"; mkdir -p "$W"; cd "$W"
fetch() { # name repo commit
  if [ ! -d "$1/.git" ]; then
    git init -q "$1" && git -C "$1" remote add origin "https://github.com/$2.git"
    git -C "$1" fetch -q --depth 1 origin "$3" && git -C "$1" -c advice.detachedHead=false checkout -q FETCH_HEAD
  fi
}
fetch dvwa       digininja/DVWA        a1978a2fed195acd093010af6395f86a281537ca
fetch mutillidae webpwnized/mutillidae 126a1fdb4ff977f87e980d018f0def477afc3d5d
fetch wordpress  WordPress/WordPress   db96f5eaa77a8d3e8eec8923a518fa2326f0d46a   # 7.1.4
fetch laravel    laravel/framework     f5c01f6b63803f16f38ebb31622c4fea412bd022   # v13.42.0
fetch symfony    symfony/symfony       eca3b7b6bd3af91752b3f4b36959520d409ee279   # v8.1.11
export PYTHONPATH="$REPO/src" PHPWARDEN_FREE_FEED_URL=off
for t in dvwa mutillidae wordpress laravel symfony; do
  s=$(python3 -c 'import time;print(time.time())')
  python3 -m phpwarden.cli code "$W/$t" --json > "$W/$t.json" || true   # exit 1 = findings
  e=$(python3 -c 'import time;print(time.time())')
  echo "$t $s $e $(git -C "$W/$t" rev-parse HEAD)" >> "$W/timing.txt.new"
done
mv "$W/timing.txt.new" "$W/timing.txt"
python3 -I "$HERE/score.py" "$W"
echo "work dir: $W"
