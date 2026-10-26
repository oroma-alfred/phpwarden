"""Feed subscription — the part a paying customer keeps current.

The engine and the base (community) feed are open and free. A subscription
provides a license key that unlocks the hosted feed channel, which is updated as
new PHP CVEs are triaged and fitted with version ranges and detection
signatures. This module is the client: it resolves the active feed (cache ->
bundled), and `update()` pulls a newer feed when a license key is present.

No network call happens without an explicit `update()`, and the tool works
fully offline on the bundled feed.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from phpwarden.vulndb import Feed

# The hosted maintained-feed channel (server/feedserver.py behind TLS). Override
# with PHPWARDEN_FEED_URL for self-hosted or staging feed servers.
DEFAULT_FEED_URL = "https://feed.phpwarden.io/v1/feed"
CACHE_DIR_DEFAULT = Path(os.environ.get("PHPWARDEN_HOME", str(Path.home() / ".phpwarden")))
CACHE_FILE = "php-cve-feed.cache.json"
# Outcome of the last `update()` that proved or disproved the license key, so
# `status()` can say license_valid True/False instead of guessing from the key
# being a non-empty string. Keyed by a hash of the key: a new key resets it.
LICENSE_STATUS_FILE = "license-status.json"
_REJECTED_HTTP = (401, 403)


def version_key(v) -> tuple:
    """Comparable key for a feed_version like '2026.10.24.1'. As STRINGS,
    '2026.10.9.1' > '2026.10.24.1', which let a stale cache beat a newer
    bundled feed; compare the dotted integers instead."""
    return tuple(int(p) if p.isdigit() else 0 for p in str(v or "").split("."))


# A served feed may never drop more than this share of any category versus the
# feed currently in effect — mirrors deploy/feed-guard.py on the server side, so
# an empty or partial document can't blank out coverage on the client.
MAX_SHRINK = 0.10


class FeedManager:
    def __init__(self, cache_dir: Path = None, license_key: str = None, feed_url: str = None):
        self.cache_dir = Path(cache_dir or CACHE_DIR_DEFAULT)
        self.license_key = license_key or os.environ.get("PHPWARDEN_LICENSE")
        self.feed_url = feed_url or os.environ.get("PHPWARDEN_FEED_URL", DEFAULT_FEED_URL)

    # --- resolve the active feed ----------------------------------------- #
    def _cache_path(self) -> Path:
        return self.cache_dir / CACHE_FILE

    def current(self) -> Feed:
        """The feed in effect: a valid cached feed if newer than bundled, else bundled."""
        bundled = Feed.bundled()
        cache = self._cache_path()
        if cache.exists():
            try:
                cached = Feed.load(cache)
                if version_key(cached.feed_version) >= version_key(bundled.feed_version):
                    return cached
            except (OSError, ValueError, KeyError):
                pass
        return bundled

    def source(self) -> str:
        cache = self._cache_path()
        if cache.exists():
            try:
                if version_key(Feed.load(cache).feed_version) >= version_key(Feed.bundled().feed_version):
                    return "subscription-cache"
            except Exception:  # noqa: BLE001
                pass
        return "bundled-community"

    # --- license validity memo ------------------------------------------- #
    def _key_id(self) -> Optional[str]:
        if not self.license_key:
            return None
        return hashlib.sha256(self.license_key.encode()).hexdigest()[:16]

    def _license_status_path(self) -> Path:
        return self.cache_dir / LICENSE_STATUS_FILE

    def _remember_license(self, valid: bool, http_status: int) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._license_status_path().write_text(json.dumps({
                "key_id": self._key_id(), "license_valid": valid,
                "http_status": http_status, "checked": int(time.time())}))
        except OSError:
            pass                                   # best-effort memo only

    def license_valid(self) -> Optional[bool]:
        """True/False once an `update()` has proven the current key accepted or
        rejected; None when no key is set or no update has been attempted yet."""
        kid = self._key_id()
        if not kid:
            return None
        try:
            memo = json.loads(self._license_status_path().read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(memo, dict) or memo.get("key_id") != kid:
            return None
        v = memo.get("license_valid")
        return v if isinstance(v, bool) else None

    # --- subscription update --------------------------------------------- #
    def update(self) -> dict:
        """Pull a newer feed if a license key is set. Returns a status dict.

        status: updated | current | no_license | unlicensed | error.
        "unlicensed" means the server answered 401/403 — the key was rejected
        (invalid or revoked); "error" is a network failure, a non-auth HTTP
        error, or a bad document. `http_status` carries the server's code when
        there was one."""
        if not self.license_key:
            return {"status": "no_license",
                    "message": "No license key set. Running on the free community feed. "
                               "Set PHPWARDEN_LICENSE to subscribe to the maintained channel.",
                    "feed_version": self.current().feed_version}
        try:
            req = urllib.request.Request(
                self.feed_url,
                headers={"Authorization": f"Bearer {self.license_key}",
                         "User-Agent": "phpwarden-feed/1"})
            with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
                raw = resp.read()
                http_status = resp.status
        except urllib.error.HTTPError as e:
            if e.code in _REJECTED_HTTP:
                self._remember_license(False, e.code)
                return {"status": "unlicensed", "http_status": e.code, "license_valid": False,
                        "message": f"the feed server rejected the license key (HTTP {e.code}); "
                                   f"check PHPWARDEN_LICENSE or renew the subscription. "
                                   f"The community feed stays in effect.",
                        "feed_version": self.current().feed_version}
            return {"status": "error", "http_status": e.code,
                    "message": f"feed fetch failed: HTTP {e.code} {e.reason}",
                    "feed_version": self.current().feed_version}
        except Exception as e:  # noqa: BLE001 — network failure
            return {"status": "error", "message": f"feed fetch failed: {e.__class__.__name__}: {e}",
                    "feed_version": self.current().feed_version}
        # a 2xx with the bearer key means the key is good, whatever the document says
        self._remember_license(True, http_status)

        # Validate the document fully BEFORE it can touch the cache: a server
        # that returns `5`, a CVE without an id, or an empty feed must leave the
        # feed in effect untouched (previously the bad doc was cached first and
        # every later update crashed on it).
        try:
            doc = json.loads(raw)
            if not isinstance(doc, dict) or "cves" not in doc or "feed_version" not in doc:
                raise ValueError("feed missing required keys")
            if not isinstance(doc["cves"], list) or not doc["cves"]:
                raise ValueError("feed has no CVEs")
            for c in doc["cves"]:
                if not isinstance(c, dict) or not c.get("id"):
                    raise ValueError("feed contains a CVE without an id")
        except (ValueError, json.JSONDecodeError, TypeError) as e:
            return {"status": "error", "http_status": http_status, "license_valid": True,
                    "message": f"invalid feed document: {e}"}

        before = self.current()
        new_ver = doc["feed_version"]
        if version_key(new_ver) <= version_key(before.feed_version):
            return {"status": "current", "feed_version": before.feed_version,
                    "http_status": http_status, "license_valid": True,
                    "message": "Already up to date."}

        # Parse into a Feed from a temp file first; only a feed that loads AND
        # keeps coverage replaces the cache.
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = self._cache_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2))
        try:
            after = Feed.load(tmp)
        except Exception as e:  # noqa: BLE001
            tmp.unlink(missing_ok=True)
            return {"status": "error", "message": f"feed failed to load: {e.__class__.__name__}: {e}"}
        for name, now, then in (("cves", len(after.cves), len(before.cves)),
                                ("composer", len(after.composer), len(before.composer)),
                                ("wp", len(after.wp), len(before.wp))):
            if then and now < then * (1 - MAX_SHRINK):
                tmp.unlink(missing_ok=True)
                return {"status": "error", "feed_version": before.feed_version,
                        "message": f"refusing feed {new_ver}: {name} advisories would drop "
                                   f"{then} -> {now}; keeping {before.feed_version}"}
        tmp.replace(self._cache_path())
        new_ids = {c.id for c in after.cves} - {c.id for c in before.cves}
        return {"status": "updated", "from": before.feed_version, "to": after.feed_version,
                "added_cves": sorted(new_ids), "total_cves": len(after.cves),
                "http_status": http_status, "license_valid": True}

    def status(self) -> dict:
        """`license_key_set` is just "a key is configured"; `license_valid` is
        None until an `update()` has had the server accept or reject that key."""
        f = self.current()
        return {"feed_version": f.feed_version, "channel": f.channel,
                "generated": f.generated, "cve_count": len(f.cves),
                "composer_count": len(f.composer), "wp_count": len(f.wp),
                "total_advisories": len(f.cves) + len(f.composer) + len(f.wp),
                "source": self.source(),
                "license_key_set": bool(self.license_key),
                "license_valid": self.license_valid()}
