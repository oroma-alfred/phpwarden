#!/usr/bin/env bash
# Full independent WordPress + enrichment build. Fetches NVD WordPress CVEs,
# imports them, re-downloads KEV/EPSS, and rebuilds the shipped feed from all
# open sources. Long-running (NVD paging is rate-limited); run in background.
set -u
cd "$(dirname "$0")/.."
OUT=feedbuilder/output
mkdir -p "$OUT/nvd-wp"

echo "[1/5] fetching NVD WordPress CVE pages..."
python3 -I feedbuilder/fetch_nvd_wordpress.py "$OUT/nvd-wp" || echo "  (fetch ended; continuing with what we have)"

echo "[2/5] importing NVD WordPress advisories..."
python3 -I feedbuilder/import_nvd_wordpress.py "$OUT"/nvd-wp/*.json "$OUT/wp_nvd.json"

echo "[3/5] downloading enrichment (KEV + EPSS)..."
curl -sSL --max-time 60 -o "$OUT/kev.json" "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
curl -sSL --max-time 90 -o "$OUT/epss.csv.gz" "https://epss.cyentia.com/epss_scores-current.csv.gz"
gunzip -kf "$OUT/epss.csv.gz"

echo "[4/5] building merged feed..."
python3 -I feedbuilder/build_feed.py \
  --base feedbuilder/base/php-cve-feed.base.json \
  --composer "$OUT/composer_osv.json" "$OUT/composer_friendsofphp.json" \
  --wp "$OUT/wp_nvd.json" \
  --out src/phpwarden/data/php-cve-feed.json \
  --feed-version 2026.10.24.1 --channel "community+osv+foph+nvd"

echo "[5/5] enriching feed (KEV + EPSS)..."
python3 -I feedbuilder/enrich.py \
  --feed src/phpwarden/data/php-cve-feed.json \
  --kev "$OUT/kev.json" --epss "$OUT/epss.csv" \
  --out src/phpwarden/data/php-cve-feed.json --feed-version 2026.10.24.1

echo "=== DONE. Final feed: ==="
PYTHONPATH=src python3 -m phpwarden.cli feed status | head -1
