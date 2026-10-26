"""PHP version parsing and branch-aware range matching.

A PHP version is (major, minor, patch) plus an optional prerelease marker. The
"branch" is (major, minor) — PHP backports security fixes per branch, so a CVE
is expressed as a fixed patch level per branch, not a single global threshold.
"""
from __future__ import annotations

import re
from typing import NamedTuple, Optional

_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)")
# Anchored to the start of the text that follows X.Y.Z: "8.3.10RC1", "8.3.10-beta2".
# Unanchored, "Architecture x64" (contains "rc") marked a patched build prerelease.
_PRERELEASE = re.compile(r"(?i)^[\s\-~_.]?(alpha|beta|rc|dev|snapshot)(?![a-z])")


class Version(NamedTuple):
    major: int
    minor: int
    patch: int
    prerelease: bool = False

    @property
    def branch(self):
        return (self.major, self.minor)

    def __str__(self):
        s = f"{self.major}.{self.minor}.{self.patch}"
        return s + " (prerelease)" if self.prerelease else s

    def _cmp_key(self):
        # A prerelease of X.Y.Z sorts just below the final X.Y.Z.
        return (self.major, self.minor, self.patch, 0 if self.prerelease else 1)

    def __lt__(self, other):
        return self._cmp_key() < other._cmp_key()

    def __ge__(self, other):
        return self._cmp_key() >= other._cmp_key()


def parse(text: str) -> Optional[Version]:
    """Extract a Version from any string containing X.Y.Z, or None."""
    if not text:
        return None
    m = _VER.search(text)
    if not m:
        return None
    tail = text[m.end():]
    return Version(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                   bool(_PRERELEASE.search(tail)))


def parse_fixed(text: str) -> Optional[Version]:
    """Parse a fixed-version string (always treated as a final release)."""
    m = _VER.search(text or "")
    if not m:
        return None
    return Version(int(m.group(1)), int(m.group(2)), int(m.group(3)), False)


def is_below_fixed(ver: Version, fixed: Version) -> bool:
    """True if `ver` is strictly below the fixed release on the same branch."""
    return ver < fixed


def compare(a: Version, b: Version) -> int:
    """-1 if a<b, 0 if equal, 1 if a>b (prerelease-aware)."""
    ka, kb = a._cmp_key(), b._cmp_key()
    return (ka > kb) - (ka < kb)


# --- loose dotted-version handling (Composer / WordPress ecosystems) -------- #
# These can be 2, 3 or 4 segments (e.g. "6.9", "5.3.2", "6.3.0.1"); compare by
# zero-padding to equal length. Build/prerelease suffixes are ignored.
_OLDSTYLE = re.compile(r"^\d+\.x-(\d.*)$")          # Drupal contrib "8.x-5.20" -> "5.20"
_LOOSE_NUM = re.compile(r"\d+(?:\.\d+)*")
_LOOSE_PRE = re.compile(r"(?i)^[-~_.]?(alpha|beta|rc|dev|snapshot|pre|a|b)\d*")


def parse_loose(s: str):
    """Tuple key for a Composer/WordPress-style version.

    Only the leading dotted numbers count ("5.3.2RC1" -> 5.3.2, not 5.3.2.1).
    A prerelease suffix appends -1 so it sorts just below the final release
    (compare_loose pads with 0): "5.3.2-beta1" < "5.3.2", so it matches "<5.3.2".
    """
    if not s:
        return None
    s = str(s).strip().lstrip("vV")
    m = _OLDSTYLE.match(s)
    if m:
        s = m.group(1)
    head = s.split("+")[0]
    core, dash, suffix = head.partition("-")
    mnum = _LOOSE_NUM.match(core)
    if not mnum:
        return None
    nums = tuple(int(n) for n in mnum.group(0).split("."))
    tail = core[mnum.end():] + (("-" + suffix) if dash else "")
    pre = bool(tail) and bool(_LOOSE_PRE.match(tail))
    return nums + ((-1,) if pre else ())


def compare_loose(a, b) -> int:
    n = max(len(a), len(b))
    a = tuple(a) + (0,) * (n - len(a))
    b = tuple(b) + (0,) * (n - len(b))
    return (a > b) - (a < b)
