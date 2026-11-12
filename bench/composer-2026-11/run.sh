#!/bin/sh
# Rerun the composer-2026-11 benchmark: phpwarden vs `composer audit` vs OSV.dev
# on four pinned lockfiles. Needs composer, python3, network (composer audit and
# api.osv.dev), and phpwarden on PATH.
#
#   sh bench/composer-2026-11/run.sh            # whatever feed your phpwarden uses
#   FEED=bundled sh bench/composer-2026-11/run.sh   # force the bundled feed
#
# Results depend on the day you run it: all three sources keep publishing.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"; cp -R "$HERE/stacks/." "$WORK/"
[ "${FEED:-}" = bundled ] && export PHPWARDEN_HOME="$WORK/.empty-home"
cd "$WORK"
for p in laravel8 symfony44 drupal9 libs; do
  ( cd "$p"
    composer audit --locked --format=json --no-interaction > audit.json || true
    phpwarden deps composer.lock --json --no-reachability > pw.json || true )
done
phpwarden feed status | head -1
python3 -I "$HERE/compare.py" laravel8 symfony44 drupal9 libs
cp results.json results.run.json
python3 -I "$HERE/reconcile.py" run
echo "work dir: $WORK"
