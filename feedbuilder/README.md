# feedbuilder — the independent advisory pipeline

Build tooling that assembles phpwarden's feed from **open primary sources we own
the right to use**, so the product needs no vendor licence. Not part of the
runtime package; it may use PyYAML, the runtime stays stdlib-only.

## Why this exists

Commercial WordPress vuln databases (Wordfence, Patchstack, WPScan) license their
*curated* data and forbid rehosting it. phpwarden does not depend on them. It
builds its own database from the same open upstreams those vendors draw from:

| Source | What | Licence | Covers |
|--------|------|---------|--------|
| [OSV.dev](https://osv.dev) (Packagist dump) | aggregated open advisories | open / CC-BY | Composer |
| [FriendsOfPHP](https://github.com/FriendsOfPHP/security-advisories) | `composer audit` dataset | open | Composer |
| [NVD](https://nvd.nist.gov) CVE 2.0 | all CVEs incl. WP plugins | public domain | WordPress, engine |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | actively-exploited flag | public domain | enrichment |
| [FIRST EPSS](https://www.first.org/epss/) | exploitation probability | open | enrichment |

A licensed vendor feed (Wordfence v3) is supported as an *optional interim*
accelerator (`fetch_wordfence.py` + `import_wordfence.py`), never a dependency.

## Pipeline

```
curated base ─┐
OSV.dev ──────┤                              ┌─ KEV  ─┐
FriendsOfPHP ─┼─ build_feed.py ─> feed.json ─┤        ├─ enrich.py ─> shipped feed
NVD (WP) ─────┘  (curated wins, ranges       └─ EPSS ─┘
                  unioned on CVE collision)
```

## 1. Composer — OSV.dev (primary, independent)

```bash
curl -sSL -o packagist.zip \
  https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip
mkdir osv && (cd osv && unzip -q ../packagist.zip)
python3 -I import_osv.py osv output/composer_osv.json      # ~11,800 advisories
```

## 2. Composer — FriendsOfPHP (fills gaps)

```bash
curl -sSL -o foph.tgz \
  https://codeload.github.com/FriendsOfPHP/security-advisories/tar.gz/refs/heads/master
mkdir foph && tar xzf foph.tgz -C foph
python3 -I import_friendsofphp.py foph/security-advisories-master output/composer_friendsofphp.json
```

## 3. WordPress — NVD (independent, license-free)

NVD tags WordPress plugin/theme CVEs with `target_sw = wordpress` in the CPE and
core as `wordpress:wordpress`. Page the NVD CVE 2.0 API (a free NVD key raises
the rate limit), save the JSON pages, then:

```bash
python3 -I fetch_nvd_wordpress.py nvd/            # writes nvd/nvd-wp-<startIndex>.json per page
python3 -I import_nvd_wordpress.py nvd/nvd-wp-*.json output/wp_nvd.json
```

NVD holds 20,000+ WordPress CVEs — the full WordPress database, no vendor licence.

### Optional interim: Wordfence v3 (licensed)

```bash
WORDFENCE_API_KEY=... python3 -I fetch_wordfence.py wordfence.json
python3 -I import_wordfence.py wordfence.json output/wp_wordfence.json
```

## 4. Merge + enrich into the shipped feed

```bash
python3 -I build_feed.py \
  --base base/php-cve-feed.base.json \
  --composer output/composer_osv.json output/composer_friendsofphp.json \
  --wp output/wp_nvd.json \
  --out ../src/phpwarden/data/php-cve-feed.json --feed-version <ver>

python3 -I enrich.py --feed ../src/phpwarden/data/php-cve-feed.json \
  --kev kev.json --epss epss.csv \
  --out ../src/phpwarden/data/php-cve-feed.json --feed-version <ver>
```

`build_feed.py` keeps curated entries and unions version ranges when the same
`(package, cve)` / `(slug, cve)` appears in several sources (slugs compare with
`_` == `-`), OR-ing `known_exploited`, taking the max CVSS, filling an
"unknown" severity from any source that has one, and keeping in `fixed` only
versions the runtime matcher says are NOT affected. `enrich.py` joins KEV +
EPSS so findings rank exploitation-first.

## 5. Quality gate

```bash
python3 -I check_feed.py ../src/phpwarden/data/php-cve-feed.json [--verbose]
```

Exit 1 on any: open-ended OR-group with a fixed version inside it, `fixed`
version inside its own affected range, duplicate `(package|slug, cve)`,
version token the matcher cannot parse, or NVD slug that differs from its CPE
product without wordpress.org-reference / curated backing. `feed-refresh.sh`
runs it before the publish gate.

## Data rules worth knowing

* **OSV ranges** are walked event by event: `introduced`/`fixed` -> `>=a,<b`
  (b recorded as a fix), `introduced`/`last_affected` -> `>=a,<=b` (no fix),
  `introduced: 0` alone -> `*` with `fixed: []` ("no fix yet"). Entries with
  only a `versions` list become exact-version groups.
* **Severity** for Composer comes from the CVSS v3 vector in the OSV record
  (`cvss.py` computes the base score); v4-only records use the source's
  label. FriendsOfPHP carries no severity, so FoPH-only advisories stay
  "unknown".
* **FriendsOfPHP "fixed"** is a branch's strict upper bound only when that
  branch records a fix `time`; a `time: ~` branch ending at the next branch's
  first release (`<2.3.0`) is an unfixed branch, not a fix.
* **NVD slugs**: the install directory is the wordpress.org slug, which NVD's
  CPE product often is not (`website_builder` -> `elementor`), and NVD
  sometimes files an add-on under its parent's CPE. When the CVE's references
  name exactly one `plugins.trac.wordpress.org` / `wordpress.org/plugins/`
  slug, that slug wins (`slug_source: wordpress.org`); the CPE is kept in
  `cpe` for audit; `base/nvd-slug-overrides.json` holds curated corrections.
  Nothing is mapped by keyword or substring.
* **Core / themes**: `cpe:2.3:a:wordpress:wordpress:...` -> kind `core`, slug
  `wordpress` (matched against `wp-includes/version.php`); a description of
  the form "... theme ... for WordPress" with no "plugin" -> kind `theme`
  (matched against `wp-content/themes/<slug>/style.css` `Version:`). NVD's
  CPE has no theme flag, so this is a description heuristic. Version-less
  core CPEs (NVD mis-assignments of plugin CVEs) are dropped.

## Legal note

Every bundled source is open or public-domain and redistributable. We do **not**
ingest, scrape, or rehost the curated databases of Wordfence, Patchstack or
WPScan — those are their licensed products. Independence comes from owning the
pipeline over open upstreams, not from copying a vendor's compilation.
