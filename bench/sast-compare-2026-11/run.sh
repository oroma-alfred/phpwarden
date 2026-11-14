#!/bin/sh
# Compare `phpwarden code` with Semgrep OSS and Psalm's taint analysis on the
# same pinned PHP codebases, then score them (score.py).
#
#   sh bench/sast-compare-2026-11/run.sh            # everything
#   TOOLS="phpwarden-tokens semgrep" sh run.sh      # a subset
#   TARGETS="dvwa mutillidae" sh run.sh
#
# Work files (targets, tools, raw results) go to $BENCH_DATA (default: a temp
# dir). Needs git, python3 (3.12 for Semgrep), php and composer. Network is used
# to fetch the targets, Semgrep, its public rule packs and Psalm.
#
# Snyk Code is not run by default: it needs an account and `snyk auth`. If you
# have one, set SNYK=1 with the snyk CLI logged in and the script adds it; this
# script never reads, prompts for or stores a token.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
W="${BENCH_DATA:-$(mktemp -d)}"; mkdir -p "$W/targets" "$W/tools" "$W/out"
TOOLS="${TOOLS:-phpwarden-tokens phpwarden-auto semgrep psalm}"
TARGETS="${TARGETS:-dvwa mutillidae wordpress laravel symfony}"
PY312="${PY312:-python3.12}"
SEMGREP_VERSION=1.185.0
PSALM_VERSION=7.5.0

fetch() { # name repo commit
  d="$W/targets/$1"
  if [ ! -d "$d/.git" ]; then
    git init -q "$d" && git -C "$d" remote add origin "https://github.com/$2.git"
    git -C "$d" fetch -q --depth 1 origin "$3" && git -C "$d" -c advice.detachedHead=false checkout -q FETCH_HEAD
  fi
}
fetch dvwa       digininja/DVWA        a1978a2fed195acd093010af6395f86a281537ca
fetch mutillidae webpwnized/mutillidae 126a1fdb4ff977f87e980d018f0def477afc3d5d
fetch wordpress  WordPress/WordPress   db96f5eaa77a8d3e8eec8923a518fa2326f0d46a   # 7.1.4
fetch laravel    laravel/framework     f5c01f6b63803f16f38ebb31622c4fea412bd022   # v13.42.0
fetch symfony    symfony/symfony       eca3b7b6bd3af91752b3f4b36959520d409ee279   # v8.1.11

# --- tools -------------------------------------------------------------------
case " $TOOLS " in *" semgrep "*)
  if [ ! -x "$W/tools/semgrep-venv/bin/semgrep" ]; then
    "$PY312" -m venv "$W/tools/semgrep-venv"
    "$W/tools/semgrep-venv/bin/pip" -q install "semgrep==$SEMGREP_VERSION"
  fi
  # Keep a copy of the exact public rule packs used, with their hashes: the
  # registry packs are not versioned, so the copy is the record.
  for pack in php owasp-top-ten; do
    curl -fsSL "https://semgrep.dev/c/p/$pack" -o "$W/out/semgrep-pack-$pack.yml" || true
  done
  ( cd "$W/out" && shasum -a 256 semgrep-pack-*.yml > semgrep-packs.sha256 2>/dev/null || true ) ;;
esac
case " $TOOLS " in *" psalm "*)
  if [ ! -x "$W/tools/psalm/vendor/bin/psalm" ]; then
    mkdir -p "$W/tools/psalm"
    ( cd "$W/tools/psalm" && composer require -q --no-interaction "vimeo/psalm:$PSALM_VERSION" )
  fi ;;
esac

# --- run -----------------------------------------------------------------------
: > "$W/out/timing.txt"
stamp() { python3 -c 'import time;print(time.time())'; }
for t in $TARGETS; do
  src="$W/targets/$t"
  for tool in $TOOLS; do
    case "$tool" in psalm|snyk) ext=sarif ;; *) ext=json ;; esac
    out="$W/out/$tool-$t.$ext"; log="$W/out/$tool-$t.log"
    s=$(stamp); rc=0
    case "$tool" in
      phpwarden-tokens|phpwarden-auto)
        eng="${tool#phpwarden-}"
        PYTHONPATH="$REPO/src" PHPWARDEN_FREE_FEED_URL=off PHPWARDEN_CODE_ENGINE="$eng" \
          python3 -m phpwarden.cli code "$src" --json > "$out" 2> "$log" || rc=$? ;;
      semgrep)
        ( cd "$src" && "$W/tools/semgrep-venv/bin/semgrep" scan --config p/php --config p/owasp-top-ten \
            --metrics=off --json --quiet --timeout 30 --exclude tests --exclude Tests --exclude vendor \
            -o "$out" . ) > "$log" 2>&1 || rc=$? ;;
      psalm)
        # Psalm needs a config and, for frameworks, their Composer dependencies
        # to resolve classes. Following its docs: a minimal config, then
        # `psalm --taint-analysis`.
        if [ -f "$src/composer.json" ] && [ ! -d "$src/vendor" ]; then
          ( cd "$src" && composer install -q --no-interaction --no-scripts --no-plugins --ignore-platform-reqs ) >> "$log" 2>&1 || true
        fi
        python3 -I "$HERE/score.py" --psalm-config "$src" > "$src/psalm-phpwarden-bench.xml"
        ( cd "$src" && php -d memory_limit=-1 "$W/tools/psalm/vendor/bin/psalm" -c psalm-phpwarden-bench.xml \
            --taint-analysis --no-cache --threads=8 --no-progress --report="$out" ) \
            >> "$log" 2>&1 || rc=$? ;;
      snyk)
        ( cd "$src" && snyk code test --sarif > "$out" ) 2>> "$log" || rc=$? ;;
    esac
    e=$(stamp)
    echo "$tool $t $s $e $rc $(git -C "$src" rev-parse HEAD)" >> "$W/out/timing.txt"
    echo "$tool $t: exit $rc, $(python3 -c "print(round($e-$s,1))") s"
  done
done
[ "${SNYK:-0}" = 1 ] && echo "note: add 'snyk' to TOOLS to run Snyk Code with your logged-in CLI"
"$W/tools/semgrep-venv/bin/semgrep" --version > "$W/out/versions.txt" 2>/dev/null || true
[ -x "$W/tools/psalm/vendor/bin/psalm" ] && "$W/tools/psalm/vendor/bin/psalm" --version >> "$W/out/versions.txt" || true
python3 -I "$HERE/score.py" "$W"
echo "work dir: $W"
