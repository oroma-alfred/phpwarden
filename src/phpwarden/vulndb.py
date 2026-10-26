"""The CVE knowledge base: load the feed, model each CVE, match a version.

The feed is a JSON document (see data/php-cve-feed.json). It is the product's
evolving content — the part a subscription keeps current. The engine that reads
it is static and open; the feed is what grows over time.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from phpwarden import version as V


@dataclass
class CVE:
    id: str
    title: str
    cls: str
    cvss: float
    severity: str
    published: str
    exploited_in_wild: bool
    sapi: List[str]
    os: List[str]
    branches: dict               # "8.3" -> {"fixed": "8.3.36"}
    eol_affected: bool
    exposure: list
    detectors: list
    remediation: str
    references: List[str]
    aka: List[str] = field(default_factory=list)
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    ransomware: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "CVE":
        return cls(
            id=d["id"], title=d.get("title", ""), cls=d.get("class", "unknown"),
            cvss=float(d.get("cvss", 0)), severity=d.get("severity", "unknown"),
            published=d.get("published", ""), exploited_in_wild=bool(d.get("exploited_in_wild")),
            sapi=d.get("sapi") or ["any"], os=d.get("os") or ["any"],
            branches=d.get("branches", {}), eol_affected=bool(d.get("eol_affected")),
            exposure=d.get("exposure", []), detectors=d.get("detectors", []),
            remediation=d.get("remediation", ""), references=d.get("references", []),
            aka=d.get("aka", []),
            epss=d.get("epss"), epss_percentile=d.get("epss_percentile"),
            ransomware=bool(d.get("ransomware")),
        )

    # --- version logic ---------------------------------------------------- #
    def _listed_branches(self):
        return sorted((tuple(int(x) for x in b.split(".")) for b in self.branches), reverse=False)

    def version_status(self, ver: V.Version) -> str:
        """VULNERABLE | PATCHED | EOL_AFFECTED | NOT_APPLICABLE for a version.

        - branch is listed: below its fixed release -> VULNERABLE, else PATCHED.
        - branch older than every listed branch: EOL_AFFECTED if the CVE marks
          end-of-life branches affected (no upstream fix), else NOT_APPLICABLE.
        - branch newer than every listed branch: NOT_APPLICABLE (the fix is
          already in that branch's first release, or the bug post-dates it).
        """
        if not self.branches:
            return "NOT_APPLICABLE"
        bkey = f"{ver.major}.{ver.minor}"
        if bkey in self.branches:
            fixed = V.parse_fixed(self.branches[bkey]["fixed"])
            return "VULNERABLE" if V.is_below_fixed(ver, fixed) else "PATCHED"
        listed = self._listed_branches()
        b = ver.branch
        if b < listed[0]:
            return "EOL_AFFECTED" if self.eol_affected else "NOT_APPLICABLE"
        return "NOT_APPLICABLE"   # newer than any listed branch

    def fixed_for(self, ver: V.Version) -> Optional[str]:
        bkey = f"{ver.major}.{ver.minor}"
        return self.branches.get(bkey, {}).get("fixed")

    def detector_kinds(self):
        return {d.get("kind") for d in self.detectors}


@dataclass
class ComposerAdvisory:
    package: str
    cve: str
    title: str
    cvss: float
    severity: str
    affected: str            # OR-groups ("A|B") of comma-AND comparators
    fixed: List[str]
    known_exploited: bool
    references: List[str]
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    ransomware: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "ComposerAdvisory":
        return cls(
            package=d["package"], cve=d.get("cve", ""), title=d.get("title", ""),
            cvss=float(d.get("cvss", 0)), severity=d.get("severity", "unknown"),
            affected=d.get("affected", ""), fixed=d.get("fixed", []),
            known_exploited=bool(d.get("known_exploited")), references=d.get("references", []),
            epss=d.get("epss"), epss_percentile=d.get("epss_percentile"),
            ransomware=bool(d.get("ransomware")),
        )


@dataclass
class WpAdvisory:
    slug: str
    type: str                # plugin | theme | core
    cve: str
    title: str
    cvss: float
    severity: str
    affected: str
    fixed: List[str]
    known_exploited: bool
    references: List[str]
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    ransomware: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "WpAdvisory":
        return cls(
            slug=d["slug"], type=d.get("type", "plugin"), cve=d.get("cve", ""),
            title=d.get("title", ""), cvss=float(d.get("cvss", 0)),
            severity=d.get("severity", "unknown"), affected=d.get("affected", ""),
            fixed=d.get("fixed", []), known_exploited=bool(d.get("known_exploited")),
            references=d.get("references", []),
            epss=d.get("epss"), epss_percentile=d.get("epss_percentile"),
            ransomware=bool(d.get("ransomware")),
        )


@dataclass
class Feed:
    feed_version: str
    channel: str
    generated: str
    cves: List[CVE]
    composer: List[ComposerAdvisory] = field(default_factory=list)
    wp: List[WpAdvisory] = field(default_factory=list)

    @classmethod
    def from_doc(cls, d: dict) -> "Feed":
        return cls(
            feed_version=d.get("feed_version", "?"),
            channel=d.get("channel", "community"),
            generated=d.get("generated", ""),
            cves=[CVE.from_dict(c) for c in d.get("cves", [])],
            composer=[ComposerAdvisory.from_dict(c) for c in d.get("composer_advisories", [])],
            wp=[WpAdvisory.from_dict(w) for w in d.get("wp_advisories", [])],
        )

    @classmethod
    def load(cls, path) -> "Feed":
        return cls.from_doc(json.loads(Path(path).read_text()))

    @classmethod
    def bundled(cls) -> "Feed":
        """Load the feed shipped inside the package.

        Uses pkgutil.get_data so it works both on disk and inside a zipapp/zip,
        where the data file is not a real filesystem path.
        """
        import pkgutil
        raw = pkgutil.get_data("phpwarden", "data/php-cve-feed.json")
        if raw:
            return cls.from_doc(json.loads(raw.decode("utf-8")))
        # dev fallback: source tree not installed as a package
        here = Path(__file__).resolve().parent
        cand = here / "data" / "php-cve-feed.json"
        if cand.exists():
            return cls.load(cand)
        raise FileNotFoundError("bundled php-cve-feed.json not found")

    def by_id(self, cve_id):
        return next((c for c in self.cves if c.id == cve_id), None)
