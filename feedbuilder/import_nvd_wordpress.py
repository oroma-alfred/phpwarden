#!/usr/bin/env python3
"""Import WordPress core/plugin/theme advisories from NVD CVE 2.0 data (license-free).

NVD is U.S. government data in the public domain. WordPress plugin and theme
CVEs are tagged in the CPE's target-software field (`...:wordpress:*`), with
the product name as the CPE product and the fixed version in
`versionEndExcluding`. WordPress core is `cpe:2.3:a:wordpress:wordpress:...`
(target_sw is `*`, not `wordpress`). This is the independent WordPress source —
no vendor licence.

Slug resolution — what the scanner matches against is the install directory,
i.e. the wordpress.org slug, and NVD's CPE product is often NOT that slug
("website_builder" for elementor, "wordfence_security" for wordfence) and is
sometimes assigned to the wrong plugin outright (an add-on filed under its
parent: CVE-2023-6630 "Contact Form 7 - Dynamic Text Extension" carries the
contact_form_7 CPE). So:
  1. exact CPE product -> slug (dashes; wp.org form), recorded as "cpe"
  2. when the CVE's references name exactly one wordpress.org plugin slug
     (plugins.trac.wordpress.org/..., wordpress.org/plugins/<slug>) and the
     CVE has exactly one WordPress product, that slug wins ("slug_source":
     "wordpress.org") — it is the vendor's own repository path
  3. base/nvd-slug-overrides.json applies curated remaps/drops ("curated")
Nothing is ever mapped by keyword or substring. check_feed.py verifies that a
slug differs from its CPE product only with reference or curated backing.

Kind: "core" for wordpress:wordpress; "theme" when the NVD description says
"... theme ... for WordPress" and never says "plugin"; otherwise "plugin".
NVD's CPE has no plugin/theme flag, so theme classification is description-
based and reported as such.

Usage:
  python3 -I import_nvd_wordpress.py <nvd-2.0.json ...> <out.json>
"""
import json
import re
import sys
from pathlib import Path

_OVERRIDES = Path(__file__).resolve().parent / "base" / "nvd-slug-overrides.json"

_THEME_RE = re.compile(r"\btheme\b(?:\s+\S+){0,8}?\s+for\s+WordPress", re.I)
_PLUGIN_WORD = re.compile(r"\bplugin\b", re.I)
_WPORG_SLUG = [
    re.compile(r"plugins\.trac\.wordpress\.org/(?:browser|log)/([a-z0-9][a-z0-9\-]*[a-z0-9])"),
    re.compile(r"plugins\.trac\.wordpress\.org/changeset/\d+/([a-z][a-z0-9\-]*[a-z0-9])"),
    re.compile(r"plugins\.trac\.wordpress\.org/changeset\?[^\s]*?(?:new|old)=\d+(?:%40|@)([a-z][a-z0-9\-]*[a-z0-9])"),
    re.compile(r"(?:^|[./])wordpress\.org/plugins/([a-z0-9][a-z0-9\-]*[a-z0-9])"),
]
_THEME_SLUG = re.compile(r"(?:^|[./])wordpress\.org/themes/([a-z0-9][a-z0-9\-]*[a-z0-9])")
_VERSION_OK = re.compile(r"^\d+(?:\.\d+)*(?:[.\-_+][0-9A-Za-z.\-]*)?$")


def _cpe_parts(criteria: str):
    parts = criteria.split(":")
    while len(parts) < 13:
        parts.append("")
    return parts            # 3 vendor, 4 product, 5 version, 10 target_sw


def _cvss(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            sev = (m.get("baseSeverity") or data.get("baseSeverity") or "unknown").lower()
            if score is not None:
                return float(score), sev
    return 0.0, "unknown"


def norm_version(v):
    """Make an NVD version token something the matcher parses, or None.
    NVD has ".51" (leading dot: BulletProof Security) and "1.0_12319"."""
    if v is None:
        return None
    v = str(v).strip().split("\\")[0]      # "2.0.1\@824267" -> "2.0.1"
    if v.startswith("."):
        v = "0" + v
    return v if _VERSION_OK.match(v) else None


def _constraint(m: dict, cpe_version: str):
    """(group, fixed, ok) for one cpeMatch. ok=False means an unparseable version."""
    parts, fixed = [], None
    for key, op in (("versionStartIncluding", ">="), ("versionStartExcluding", ">")):
        if m.get(key):
            v = norm_version(m[key])
            if v is None:
                return None, None, False
            parts.append(op + v)
    if m.get("versionEndExcluding"):
        v = norm_version(m["versionEndExcluding"])
        if v is None:
            return None, None, False
        parts.append("<" + v)
        fixed = v
    elif m.get("versionEndIncluding"):
        v = norm_version(m["versionEndIncluding"])
        if v is None:
            return None, None, False
        parts.append("<=" + v)
    if parts:
        return ",".join(parts), fixed, True
    if cpe_version and cpe_version not in ("*", "-"):
        v = norm_version(cpe_version)
        if v is None:
            return None, None, False
        return "=" + v, None, True      # exact-version CPE: only that version
    return "*", None, True              # version-agnostic: all versions affected


def wporg_slugs(refs):
    """Distinct wordpress.org plugin slugs named by the CVE's reference URLs."""
    out = []
    for u in refs:
        for rx in _WPORG_SLUG:
            mm = rx.search(u)
            if mm and mm.group(1) not in out:
                out.append(mm.group(1))
    return out


def _dash(slug: str) -> str:
    return slug.strip().lower().replace("_", "-")


def convert(cve: dict, overrides: dict, stats: dict):
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d["value"]
            break
    title = desc[:200]
    score, sev = _cvss(cve)
    refs = [r["url"] for r in cve.get("references", [])]
    is_theme = bool(_THEME_RE.search(desc)) and not _PLUGIN_WORD.search(desc)
    by_product = {}
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                p = _cpe_parts(m.get("criteria", ""))
                vendor, product, version, target_sw = p[3], p[4], p[5], p[10]
                if vendor == "wordpress" and product == "wordpress":
                    kind = "core"
                elif target_sw == "wordpress" and product and product != "*":
                    kind = "theme" if is_theme else "plugin"
                else:
                    continue
                grp, fixed, ok = _constraint(m, version)
                if not ok:
                    stats["unparseable_versions"] += 1
                    continue
                rec = by_product.setdefault((kind, vendor, product), {"groups": [], "fixed": []})
                rec["groups"].append(grp)
                if fixed:
                    rec["fixed"].append(fixed)
    # A version-less CPE ("*") next to bounded ones carries no information:
    # the bounded groups are the analyst's statement. A version-less core CPE
    # on its own is an NVD mis-assignment (plugin CVEs filed under
    # wordpress:wordpress with no version, e.g. CVE-2007-2627) — core always
    # has a fixed release — so it is dropped rather than flag every install.
    for key, rec in list(by_product.items()):
        if "*" in rec["groups"] and any(g != "*" for g in rec["groups"]):
            rec["groups"] = [g for g in rec["groups"] if g != "*"]
        if key[0] == "core" and rec["groups"] == ["*"]:
            stats["core_versionless_dropped"] += 1
            del by_product[key]
    if not by_product:
        return []

    cve_id = cve.get("id", "")
    ov = overrides.get(cve_id)
    if ov and ov.get("drop"):
        stats["curated_dropped"] += 1
        return []
    ref_slugs = wporg_slugs(refs)
    non_core = [k for k in by_product if k[0] != "core"]
    out = []
    for (kind, vendor, product), rec in by_product.items():
        slug, slug_source = (_dash(product) if kind != "core" else "wordpress"), "cpe"
        if kind != "core":
            if ov and ov.get("slug"):
                slug, slug_source = _dash(ov["slug"]), "curated"
                kind = ov.get("type", kind)
                stats["curated_remapped"] += 1
            elif len(non_core) == 1 and len(ref_slugs) == 1 and kind == "plugin" \
                    and ref_slugs[0] != slug:
                slug, slug_source = ref_slugs[0], "wordpress.org"
                stats["ref_remapped"] += 1
        groups = list(dict.fromkeys(rec["groups"]))
        fixed = list(dict.fromkeys(rec["fixed"]))
        adv = {
            "slug": slug, "type": kind, "cve": cve_id,
            "title": title, "cvss": score, "severity": sev,
            "affected": "|".join(groups), "fixed": fixed,
            "known_exploited": False,
            "references": refs[:3],
            "source": "nvd",
            "cpe": f"{vendor}:{product}",
        }
        if slug_source != "cpe":
            adv["slug_source"] = slug_source
        stats[kind] += 1
        out.append(adv)
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    *sources, out = sys.argv[1:]
    overrides = {}
    if _OVERRIDES.exists():
        overrides = {k: v for k, v in json.loads(_OVERRIDES.read_text()).items()
                     if k.startswith("CVE-")}
    stats = {"core": 0, "plugin": 0, "theme": 0, "unparseable_versions": 0,
             "ref_remapped": 0, "curated_remapped": 0, "curated_dropped": 0,
             "core_versionless_dropped": 0}
    advisories, cves = [], 0
    for src in sources:
        doc = json.loads(Path(src).read_text())
        for item in doc.get("vulnerabilities", []):
            cves += 1
            advisories.extend(convert(item.get("cve", {}), overrides, stats))
    Path(out).write_text(json.dumps(advisories, indent=1))
    slugs = len({(a["type"], a["slug"]) for a in advisories})
    print(f"imported {len(advisories)} WordPress advisories across {slugs} slugs "
          f"from {cves} NVD CVEs -> {out}")
    print(f"  kinds: {stats['plugin']} plugin, {stats['theme']} theme (description-classified), "
          f"{stats['core']} core")
    print(f"  slugs taken from wordpress.org reference URLs: {stats['ref_remapped']}; "
          f"curated remaps: {stats['curated_remapped']}, curated drops: {stats['curated_dropped']}")
    print(f"  cpeMatch entries skipped for unparseable versions: {stats['unparseable_versions']}; "
          f"version-less core CPEs dropped: {stats['core_versionless_dropped']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
