"""phpwarden probe -- a safe, non-intrusive live HTTP check of a PHP/WordPress site.

SAFETY RULES (these are the design, not suggestions):

* GET/HEAD only. No POST, no payloads, no fuzzing, no brute force, no login or
  auth attempts, no form submission. Nothing is ever written to the target.
* No crawling. Only the homepage plus a FIXED list of well-known paths is ever
  requested (see EXPOSURE_CHECKS / ENDPOINT_CHECKS below). Links found on a
  page are never followed; the only page-derived requests are
  `wp-content/plugins/<slug>/readme.txt` for plugin slugs already referenced on
  the homepage. Because nothing is crawled, robots.txt is not consulted.
* Ownership gate. PASSIVE mode (default) makes exactly ONE HTTP request: a GET
  of the URL given. Headers, cookies, TLS and HTML meta are read from that one
  response (the TLS certificate expiry is read from a bare TLS handshake, not
  an HTTP request). ACTIVE mode (the path lists) runs only after
  `verify_ownership` succeeds via DNS TXT, a /.well-known file, or a homepage
  meta tag carrying a caller-issued token.
* Politeness. Identifying User-Agent, hard request cap (default 60), delay
  between requests (default 0.3s), 8s per-request timeout, 90s total time cap,
  at most 3 redirects and never to a different host, at most 256 KB read per
  response.
* No secrets in output. Evidence names what was found (e.g. the variable NAMES
  in an exposed .env, the NUMBER of enumerable users) and never values.
* Every exposure is content-confirmed; status 200 alone never counts, and a
  random nonexistent path is requested first to detect soft-404 sites.
"""
import difflib
import hashlib
import hmac
import http.client
import json
import re
import secrets as _secrets
import shutil
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from . import __version__
from . import version as V
from .deps import constraint_matches, scan_lock_doc
from .engine import Environment, assess_one

USER_AGENT = f"phpwarden-probe/{__version__} (+https://phpwarden.io/probe)"
TIMEOUT = 8.0
TOTAL_TIME_CAP = 90.0
MAX_BYTES = 256 * 1024
MAX_REDIRECTS = 3
MAX_README_FETCHES = 10

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


# --------------------------------------------------------------------------- #
# HTTP plumbing
# --------------------------------------------------------------------------- #
class Response:
    """Minimal response: status, headers as list of (lower-name, value), body."""
    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = [(k.lower(), v) for k, v in headers]
        self.body = body or b""
        self.url = url

    def header(self, name, default=None):
        name = name.lower()
        for k, v in self.headers:
            if k == name:
                return v
        return default

    def all(self, name):
        name = name.lower()
        return [v for k, v in self.headers if k == name]

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")


def default_fetch(url, method="GET", timeout=TIMEOUT, max_bytes=MAX_BYTES):
    """Single HTTP request, no redirect following. Returns a Response."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout,
                                           context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(max_bytes) if method != "HEAD" else b""
        return Response(r.status, r.getheaders(), body, url)
    finally:
        conn.close()


class BudgetExceeded(Exception):
    pass


class _Session:
    """Enforces request cap, delay, total time cap and same-host redirects."""
    def __init__(self, base_url, fetch, max_requests, delay):
        self.host = (urlsplit(base_url).hostname or "").lower()
        self.fetch = fetch or default_fetch
        self.max_requests = max_requests
        self.delay = delay
        self.count = 0
        self.start = time.monotonic()
        self.notes = []

    def _one(self, url, method):
        if self.count >= self.max_requests:
            raise BudgetExceeded("request cap reached")
        if time.monotonic() - self.start > TOTAL_TIME_CAP:
            raise BudgetExceeded("time cap reached")
        if self.count and self.delay:
            time.sleep(self.delay)
        self.count += 1
        return self.fetch(url, method=method, timeout=TIMEOUT, max_bytes=MAX_BYTES)

    def get(self, url, follow=True, method="GET"):
        """GET url, following <=3 same-host redirects. Returns Response or None."""
        try:
            r = self._one(url, method)
            hops = 0
            while follow and r.status in (301, 302, 303, 307, 308) and r.header("location"):
                nxt = urljoin(r.url, r.header("location"))
                if (urlsplit(nxt).hostname or "").lower() != self.host:
                    self.notes.append(f"redirect to another host not followed: {urlsplit(nxt).hostname}")
                    return r
                if hops >= MAX_REDIRECTS:
                    self.notes.append("redirect limit reached")
                    return r
                hops += 1
                r = self._one(nxt, method)
            return r
        except BudgetExceeded:
            raise
        except (OSError, http.client.HTTPException, ValueError) as e:
            self.notes.append(f"{urlsplit(url).path or '/'}: {type(e).__name__}")
            return None


# --------------------------------------------------------------------------- #
# Ownership
# --------------------------------------------------------------------------- #
def generate_token(host, secret):
    """Stable per-host token: HMAC-SHA256(secret, host) hex, first 32 chars."""
    key = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(key, host.strip().lower().encode(), hashlib.sha256).hexdigest()[:32]


_META_VERIFY_RE = re.compile(
    r"""<meta\s+[^>]*name=["']phpwarden-verify["'][^>]*content=["']([^"']+)["']"""
    r"""|<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["']phpwarden-verify["']""", re.I)


def _meta_has_token(html, token):
    return any(token in (a or b) for a, b in _META_VERIFY_RE.findall(html or ""))


def _dns_txt_has_token(host, token):
    """DNS TXT via `dig +short TXT` (stdlib has no TXT resolver). Skipped for
    IP literals or when dig is unavailable."""
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return False                       # IP literal: no DNS name to check
    except OSError:
        pass
    dig = shutil.which("dig")
    if not dig:
        return False
    try:
        out = subprocess.run([dig, "+short", "+time=3", "+tries=1", "TXT", host],
                             capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return f"phpwarden-verify={token}" in out.replace('" "', "").replace('"', "")


def verify_ownership(base_url, token, *, fetch=None, homepage_html=None, _session=None):
    """(verified, method) -- method is "dns" | "well-known" | "meta" | None.

    Tries the cheapest evidence first: the already-fetched homepage meta tag,
    then DNS TXT (no HTTP request), then /.well-known/phpwarden-verify.txt."""
    if not token:
        return False, None
    sess = _session or _Session(base_url, fetch, 3, 0)
    parts = urlsplit(base_url)
    root = f"{parts.scheme}://{parts.netloc}/"
    if homepage_html is None:
        r = sess.get(base_url)
        homepage_html = r.text if r is not None and r.status == 200 else ""
    if _meta_has_token(homepage_html, token):
        return True, "meta"
    if _dns_txt_has_token(parts.hostname or "", token):
        return True, "dns"
    r = sess.get(urljoin(root, ".well-known/phpwarden-verify.txt"))
    if r is not None and r.status == 200 and token in r.text:
        return True, "well-known"
    return False, None


# --------------------------------------------------------------------------- #
# Content validators for exposed files (status 200 alone never counts)
# --------------------------------------------------------------------------- #
_ENV_LINE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=")
_PHP_LOG = re.compile(r"PHP (?:Fatal error|Warning|Notice|Deprecated|Parse error|Stack trace)")
_LARAVEL_LOG = re.compile(r"\[\d{4}-\d\d-\d\d[ T][\d:]+[^\]]*\]\s+\w+\.(?:ERROR|WARNING|INFO|DEBUG|CRITICAL|NOTICE)")


def _v_env(r):
    names = list(dict.fromkeys(_ENV_LINE.findall(r.text)))
    if len(names) < 2 or "<html" in r.text[:500].lower():
        return None
    shown = ", ".join(names[:10]) + (f" (+{len(names) - 10} more)" if len(names) > 10 else "")
    return f"{len(names)} variables exposed (names only): {shown}"


def _v_git_head(r):
    return "repository HEAD readable (ref: ...)" if r.text.lstrip().startswith("ref:") else None


def _v_git_config(r):
    return "git config readable ([core] section)" if "[core]" in r.text else None


def _json(r):
    try:
        return json.loads(r.text)
    except ValueError:
        return None


def _v_composer_lock(r):
    d = _json(r)
    if isinstance(d, dict) and isinstance(d.get("packages"), list):
        return f"composer.lock readable ({len(d['packages'])} packages)"
    return None


def _v_composer_json(r):
    d = _json(r)
    if isinstance(d, dict) and ("require" in d or "autoload" in d):
        return "composer.json readable (dependency manifest)"
    return None


def _v_phpinfo(r):
    t = r.text
    return "phpinfo() output exposed" if "PHP Version" in t and "phpinfo" in t.lower() else None


def _v_wpconfig(r):
    t = r.text
    if "DB_PASSWORD" in t or ("define(" in t and "DB_NAME" in t):
        return "wp-config backup readable as plain text (DB credentials defines present; values not shown)"
    return None


def _v_dsstore(r):
    return ".DS_Store file listing exposed" if r.body[:8] == b"\x00\x00\x00\x01Bud1" else None


def _v_zip(r):
    return "ZIP archive downloadable" if r.body[:4] == b"PK\x03\x04" else None


def _v_sql(r):
    t = r.text[:65536]
    if re.search(r"(?i)-- MySQL dump|CREATE TABLE|INSERT INTO|-- PostgreSQL database dump", t) \
            and "<html" not in t[:500].lower():
        return "SQL dump downloadable"
    return None


def _v_phplog(r):
    n = len(_PHP_LOG.findall(r.text))
    return f"PHP error log readable ({n} log lines in first 256 KB)" if n else None


def _v_laravel_log(r):
    n = len(_LARAVEL_LOG.findall(r.text))
    return f"Laravel log readable ({n} log entries in first 256 KB)" if n else None


# (id, path, severity, title, validator, fix)
EXPOSURE_CHECKS = [
    ("exposed-env", ".env", "critical", "Exposed .env file", _v_env,
     "Block dotfiles in the web server and rotate every secret in the file."),
    ("exposed-env-backup", ".env.backup", "critical", "Exposed .env backup", _v_env,
     "Delete the backup and rotate every secret in it."),
    ("exposed-git-head", ".git/HEAD", "critical", "Exposed .git repository", _v_git_head,
     "Deny access to /.git; the full source history may be downloadable."),
    ("exposed-git-config", ".git/config", "critical", "Exposed .git/config", _v_git_config,
     "Deny access to /.git and check the config for embedded credentials."),
    ("exposed-composer-lock", "composer.lock", "medium", "Exposed composer.lock", _v_composer_lock,
     "Keep composer files outside the web root."),
    ("exposed-composer-json", "composer.json", "low", "Exposed composer.json", _v_composer_json,
     "Keep composer files outside the web root."),
    ("exposed-phpinfo", "phpinfo.php", "high", "phpinfo() page exposed", _v_phpinfo,
     "Delete the file."),
    ("exposed-info-php", "info.php", "high", "phpinfo() page exposed", _v_phpinfo,
     "Delete the file."),
    ("exposed-wpconfig-bak", "wp-config.php.bak", "critical", "wp-config.php backup exposed", _v_wpconfig,
     "Delete the backup and rotate DB credentials and salts."),
    ("exposed-wpconfig-tilde", "wp-config.php~", "critical", "wp-config.php editor backup exposed", _v_wpconfig,
     "Delete the backup and rotate DB credentials and salts."),
    ("exposed-wpconfig-save", "wp-config.php.save", "critical", "wp-config.php backup exposed", _v_wpconfig,
     "Delete the backup and rotate DB credentials and salts."),
    ("exposed-ds-store", ".DS_Store", "low", "Exposed .DS_Store", _v_dsstore, "Delete the file."),
    ("exposed-backup-zip", "backup.zip", "critical", "Site backup archive downloadable", _v_zip,
     "Move backups out of the web root."),
    ("exposed-backup-sql", "backup.sql", "critical", "Database dump downloadable", _v_sql,
     "Move dumps out of the web root and rotate credentials."),
    ("exposed-database-sql", "database.sql", "critical", "Database dump downloadable", _v_sql,
     "Move dumps out of the web root and rotate credentials."),
    ("exposed-debug-log", "debug.log", "high", "PHP debug log exposed", _v_phplog,
     "Disable public logging and delete the file."),
    ("exposed-wp-debug-log", "wp-content/debug.log", "high", "WordPress debug.log exposed", _v_phplog,
     "Set WP_DEBUG_LOG to a path outside the web root and delete the file."),
    ("exposed-laravel-log", "storage/logs/laravel.log", "high", "Laravel log exposed", _v_laravel_log,
     "Point the web root at /public only."),
    ("exposed-error-log", "error_log", "high", "PHP error_log exposed", _v_phplog,
     "Delete the file and log outside the web root."),
]


# --------------------------------------------------------------------------- #
# Debug / admin endpoints
# --------------------------------------------------------------------------- #
def _e_ignition(r):
    return "Ignition health-check reachable (can_execute_commands)" if "can_execute_commands" in r.text else None


def _e_marker(*markers):
    def v(r):
        t = r.text
        return f"page identifies as {markers[0]}" if any(m in t for m in markers) else None
    return v


def _e_xmlrpc(r):
    return "XML-RPC enabled" if "XML-RPC server accepts POST requests only" in r.text else None


def _e_users(r):
    d = _json(r)
    if isinstance(d, list) and d and all(isinstance(u, dict) and "slug" in u for u in d):
        return f"{len(d)} usernames enumerable via REST API (names not stored)"
    return None


def _e_server_status(r):
    return "Apache server-status exposed" if "Apache Server Status" in r.text else None


# (id, path, severity, title, validator, fix, framework, cve)
ENDPOINT_CHECKS = [
    ("laravel-ignition", "_ignition/health-check", "critical",
     "Laravel Ignition endpoint exposed (CVE-2021-3129 class RCE)", _e_ignition,
     "Set APP_DEBUG=false in production and upgrade facade/ignition >= 2.5.2.", "laravel", "CVE-2021-3129"),
    ("laravel-telescope", "telescope", "high", "Laravel Telescope dashboard exposed",
     _e_marker("Laravel Telescope", "Telescope"), "Restrict Telescope to local or authorised users.", "laravel", None),
    ("laravel-horizon", "horizon", "high", "Laravel Horizon dashboard exposed",
     _e_marker("Laravel Horizon", "Horizon"), "Gate Horizon behind authorisation.", "laravel", None),
    ("symfony-profiler", "_profiler", "high", "Symfony profiler exposed",
     _e_marker("Symfony Profiler", "sf-toolbar"), "Disable the profiler/debug mode in production.", "symfony", None),
    ("symfony-app-dev", "app_dev.php", "high", "Symfony dev front controller exposed",
     _e_marker("Symfony", "sf-toolbar"), "Delete app_dev.php from production.", "symfony", None),
    ("adminer-exposed", "adminer.php", "high", "Adminer database UI exposed",
     _e_marker("Adminer"), "Remove Adminer or restrict it by IP.", None, None),
    ("phpmyadmin-exposed", "phpmyadmin/", "high", "phpMyAdmin exposed",
     _e_marker("phpMyAdmin"), "Restrict phpMyAdmin by IP or VPN.", None, None),
    ("wp-xmlrpc", "xmlrpc.php", "medium", "WordPress XML-RPC enabled", _e_xmlrpc,
     "Disable XML-RPC unless Jetpack/apps need it (brute-force amplification).", "wordpress", None),
    ("wp-user-enum", "wp-json/wp/v2/users", "medium", "WordPress REST API user enumeration", _e_users,
     "Restrict the users endpoint to authenticated requests.", "wordpress", None),
    ("server-status", "server-status", "medium", "Apache server-status exposed", _e_server_status,
     "Restrict mod_status to localhost.", None, None),
]


# --------------------------------------------------------------------------- #
# Fingerprinting
# --------------------------------------------------------------------------- #
_GEN_RE = re.compile(r"""<meta\s+[^>]*name=["']generator["'][^>]*content=["']WordPress\s+([\d.]+)""", re.I)
_FEED_GEN_RE = re.compile(r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>", re.I)
_WPINC_VER_RE = re.compile(r"/wp-includes/[^\"'\s>]+\?ver=([\d.]+)", re.I)
_ASSET_RE = re.compile(r"/wp-content/(plugins|themes)/([a-z0-9_\-.]+)/[^\"'\s>]*?(?:\?ver=([\w.\-]+))?[\"'\s>]", re.I)
_PHP_VER_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I)
_STABLE_TAG_RE = re.compile(r"(?im)^\s*Stable tag:\s*([\d][\w.\-]*)")


def _fingerprint_html(html, fp):
    m = _GEN_RE.search(html) or _WPINC_VER_RE.search(html)
    if m and not fp["wordpress"]:
        fp["wordpress"] = m.group(1)
    if "/wp-content/" in html or "/wp-includes/" in html:
        if "wordpress" not in fp["frameworks"]:
            fp["frameworks"].append("wordpress")
    for kind, slug, ver in _ASSET_RE.findall(html):
        bucket = fp["plugins"] if kind.lower() == "plugins" else fp["themes"]
        slug = slug.lower()
        if ver and (bucket.get(slug) in (None, "")):
            bucket[slug] = ver
        else:
            bucket.setdefault(slug, "")


def _fingerprint_headers(r, fp):
    for h in ("x-powered-by", "server"):
        m = _PHP_VER_RE.search(r.header(h, "") or "")
        if m and not fp["php"]:
            fp["php"] = m.group(1)
    cookies = " ".join(r.all("set-cookie")).lower()
    if "laravel_session" in cookies or "xsrf-token" in cookies:
        fp["frameworks"].append("laravel")
    if "symfony" in cookies or r.header("x-debug-token"):
        fp["frameworks"].append("symfony")
    if r.header("x-pingback") or "wordpress_" in cookies:
        fp["frameworks"].append("wordpress")
    fp["frameworks"][:] = list(dict.fromkeys(fp["frameworks"]))


# --------------------------------------------------------------------------- #
# Header / transport checks (passive-safe: they read one response)
# --------------------------------------------------------------------------- #
def _f(fid, kind, severity, title, evidence, url, fix=None, **kw):
    d = {"id": fid, "kind": kind, "severity": severity, "title": title,
         "evidence": evidence, "url": url, "known_exploited": False}
    if fix:
        d["fix"] = fix
    d.update({k: v for k, v in kw.items() if v is not None})
    return d


def _header_findings(r, url):
    out = []
    https = urlsplit(r.url).scheme == "https"
    if not https:
        loc = r.header("location", "") or ""
        if r.status in (301, 302, 307, 308) and loc.startswith("https://"):
            pass
        else:
            out.append(_f("no-https-redirect", "header", "medium", "HTTP is served without redirecting to HTTPS",
                          f"GET {url} returned {r.status} over plain HTTP", url,
                          "Redirect all HTTP traffic to HTTPS."))
    else:
        if not r.header("strict-transport-security"):
            out.append(_f("missing-hsts", "header", "low", "Missing Strict-Transport-Security",
                          "no HSTS header", url, "Add Strict-Transport-Security: max-age=31536000."))
    csp = r.header("content-security-policy", "") or ""
    if not csp:
        out.append(_f("missing-csp", "header", "low", "Missing Content-Security-Policy",
                      "no CSP header", url, "Add a Content-Security-Policy."))
    if not r.header("x-frame-options") and "frame-ancestors" not in csp:
        out.append(_f("missing-frame-options", "header", "low", "No clickjacking protection",
                      "no X-Frame-Options or CSP frame-ancestors", url,
                      "Add X-Frame-Options: SAMEORIGIN or CSP frame-ancestors."))
    if (r.header("x-content-type-options", "") or "").lower() != "nosniff":
        out.append(_f("missing-xcto", "header", "low", "Missing X-Content-Type-Options: nosniff",
                      "header absent", url, "Add X-Content-Type-Options: nosniff."))
    if not r.header("referrer-policy"):
        out.append(_f("missing-referrer-policy", "header", "low", "Missing Referrer-Policy",
                      "header absent", url, "Add Referrer-Policy: strict-origin-when-cross-origin."))
    for c in r.all("set-cookie"):
        name = c.split("=", 1)[0].strip()
        attrs = c.lower()
        missing = [a for a, key in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if not re.search(r";\s*" + key + r"\b", attrs)]
        if missing and not (not https and missing == ["Secure"]):
            out.append(_f(f"cookie-flags-{name.lower()}", "header", "low",
                          f"Cookie {name} missing {', '.join(missing)}",
                          f"Set-Cookie {name} without {'/'.join(missing)} (value not shown)", url,
                          "Set Secure; HttpOnly; SameSite=Lax on session cookies."))
    for h in ("x-powered-by", "server"):
        v = r.header(h)
        if v and re.search(r"\d", v):
            out.append(_f(f"disclosure-{h}", "header", "info", f"{h.title()} discloses version",
                          f"{h}: {v[:80]}", url, f"Remove or genericise the {h} header."))
    acao = r.header("access-control-allow-origin")
    if acao == "*" and (r.header("access-control-allow-credentials", "") or "").lower() == "true":
        out.append(_f("cors-wildcard-credentials", "header", "medium", "CORS allows any origin with credentials",
                      "Access-Control-Allow-Origin: * with Allow-Credentials: true", url,
                      "Reflect only trusted origins."))
    return out


def tls_days_left(host, port=443, timeout=TIMEOUT):
    """Days until the certificate expires, via a bare TLS handshake (no HTTP)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            cert = ss.getpeercert()
    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    return (exp - datetime.now(timezone.utc)).days


def _tls_findings(url, tls_check):
    p = urlsplit(url)
    if p.scheme != "https":
        return [], None
    try:
        days = tls_check(p.hostname, p.port or 443)
    except (OSError, ssl.SSLError, ValueError, KeyError) as e:
        return [_f("tls-error", "tls", "high", "TLS handshake failed or certificate invalid",
                   type(e).__name__, url, "Install a valid certificate.")], None
    if days < 0:
        return [_f("tls-expired", "tls", "high", "TLS certificate expired", f"expired {-days} days ago",
                   url, "Renew the certificate.")], days
    if days < 14:
        return [_f("tls-expiring", "tls", "medium", "TLS certificate expires soon", f"{days} days left",
                   url, "Renew the certificate.")], days
    if days < 30:
        return [_f("tls-expiring", "tls", "low", "TLS certificate expires within 30 days", f"{days} days left",
                   url, "Renew the certificate.")], days
    return [], days


# --------------------------------------------------------------------------- #
# Feed matching (reuses deps.constraint_matches / engine.assess_one)
# --------------------------------------------------------------------------- #
def _norm_slug(s):
    return s.strip().lower().replace("_", "-")


def _fix_for(installed, fixed) -> str:
    """The upgrade that applies to the installed version: the fixed release on
    the same branch (6.4.2 -> 6.4.12), else the lowest fixed release above it.
    Listing every branch's fix (4.7.37 / ... / 7.1.2) buries the one that matters."""
    if not fixed:
        return "Upgrade to a fixed release."
    iv = V.parse_loose(installed)
    if iv is None:
        return "Upgrade to " + " / ".join(fixed[:4])
    parsed = [(f, V.parse_loose(f)) for f in fixed]
    parsed = [(f, v) for f, v in parsed if v is not None]
    same = [f for f, v in parsed if v[:2] == iv[:2] and v > iv]
    if same:
        return f"Upgrade to {same[0]} or later"
    above = sorted((v, f) for f, v in parsed if v > iv)
    return f"Upgrade to {above[0][1]} or later" if above else "Upgrade to a fixed release."


def _vuln_findings(fp, feed, url):
    out = []
    by_key = {}
    for adv in feed.wp:
        by_key.setdefault((adv.type, _norm_slug(adv.slug)), []).append(adv)
    comps = []
    if fp["wordpress"]:
        comps.append(("core", "wordpress", fp["wordpress"]))
    comps += [("plugin", s, v) for s, v in fp["plugins"].items() if v]
    comps += [("theme", s, v) for s, v in fp["themes"].items() if v]
    for kind, slug, ver in comps:
        for adv in by_key.get((kind, _norm_slug(slug)), []):
            if adv.affected and constraint_matches(ver, adv.affected):
                label = "WordPress core" if kind == "core" else f"{kind} {slug}"
                out.append(_f(f"vuln-{adv.cve or 'nocve'}-{_norm_slug(slug)}", "vuln",
                              adv.severity if adv.severity in SEV_ORDER else "medium",
                              f"{label} {ver}: {adv.title or adv.cve}",
                              f"{label} {ver} matches affected range", url,
                              _fix_for(ver, adv.fixed),
                              cve=adv.cve or None, known_exploited=adv.known_exploited, epss=adv.epss))
    if fp["php"]:
        pv = V.parse(fp["php"])
        if pv:
            env = Environment(version=pv)       # SAPI/OS unknown -> "possibly"
            for cve in feed.cves:
                f = assess_one(cve, env)
                if not f.exposed:
                    continue
                out.append(_f(f"vuln-{cve.id}-php", "vuln",
                              cve.severity if cve.severity in SEV_ORDER else "medium",
                              f"PHP {fp['php']}: {cve.title or cve.id}"
                              + ("" if f.verdict == "EXPOSED" else " (possibly)"),
                              "; ".join(f.reasons)[:200], url,
                              f"Upgrade PHP to {f.fixed}" if f.fixed else (cve.remediation or None),
                              cve=cve.id, known_exploited=cve.exploited_in_wild, epss=cve.epss))
    return out


def _lock_findings(doc, feed, url):
    out = []
    for d in scan_lock_doc(doc, feed):
        a = d.advisory
        out.append(_f(f"vuln-{a.cve or 'nocve'}-{a.package}", "vuln",
                      a.severity if a.severity in SEV_ORDER else "medium",
                      f"{a.package} {d.installed}: {a.title or a.cve}",
                      f"{a.package} {d.installed} listed in exposed composer.lock", url,
                      ("Upgrade to " + " / ".join(a.fixed)) if a.fixed else None,
                      cve=a.cve or None, known_exploited=a.known_exploited, epss=a.epss))
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def rank(findings):
    """Known exploited first; then confirmed exposures and endpoints that are
    critical/high (a downloadable .env is certain, a version match is not);
    then EPSS desc; then severity."""
    def confirmed(f):
        return f.get("kind") in ("exposure", "endpoint") and f["severity"] in ("critical", "high")
    return sorted(findings, key=lambda f: (0 if f.get("known_exploited") else 1,
                                           0 if confirmed(f) else 1,
                                           -(f.get("epss") or 0), SEV_ORDER.get(f["severity"], 9), f["id"]))


def _soft404_sig(r, path):
    """Hash of a 200 response with the requested path blanked out, so a
    catch-all page that echoes the URL still compares equal."""
    if r is None or r.status != 200:
        return None
    body = r.body
    for variant in (path, "/" + path):
        body = body.replace(variant.encode(), b"")
    return hashlib.sha256(body).hexdigest()


def _run_active(sess, root, fp, feed, findings):
    rnd = f"phpwarden-probe-{_secrets.token_hex(8)}.txt"
    soft = sess.get(urljoin(root, rnd))
    soft_sig = _soft404_sig(soft, rnd)
    if soft_sig:
        sess.notes.append("site returns 200 for nonexistent paths (soft-404); relying on content checks")

    def same_as_catch_all(r, path, validator=None):
        """On a site that answers 200 for anything, is this response just the
        catch-all page? Three tests, because such pages often change on every
        request (nonces, timestamps, the echoed URL): identical once the path
        is blanked; nearly identical text; or the check's own marker is
        already present on the page served for a random nonexistent path."""
        if not soft_sig:
            return False
        if _soft404_sig(r, path) == soft_sig:
            return True
        if validator is not None:
            try:
                if validator(soft):
                    return True
            except Exception:  # noqa: BLE001 — a validator choking on the baseline proves nothing
                pass
        a, b = soft.text[:20000], r.text[:20000]
        return bool(a) and difflib.SequenceMatcher(None, a, b, autojunk=False).quick_ratio() > 0.95 \
            and difflib.SequenceMatcher(None, a, b, autojunk=False).ratio() > 0.9

    def hit(path, validator):
        r = sess.get(urljoin(root, path))
        if r is None or r.status != 200 or not r.body:
            return None, None
        if same_as_catch_all(r, path, validator):
            return None, None
        return validator(r), r

    for fid, path, sev, title, val, fix in EXPOSURE_CHECKS:
        ev, r = hit(path, val)
        if ev:
            u = urljoin(root, path)
            findings.append(_f(fid, "exposure", sev, title, ev, u, fix))
            if fid == "exposed-composer-lock":
                findings.extend(_lock_findings(_json(r), feed, u))

    for fid, path, sev, title, val, fix, fw, cve in ENDPOINT_CHECKS:
        ev, r = hit(path, val)
        if not ev:
            continue
        if fw and fw not in fp["frameworks"]:
            fp["frameworks"].append(fw)
        kw = {}
        if cve:
            adv = next((a for a in feed.composer if a.cve == cve), None)
            kw = {"cve": cve, "known_exploited": adv.known_exploited if adv else True,
                  "epss": adv.epss if adv else None}
        findings.append(_f(fid, "endpoint", sev, title, ev, urljoin(root, path), fix, **kw))

    # WordPress version fallbacks + plugin readmes (only slugs seen on the page)
    if "wordpress" in fp["frameworks"]:
        if not fp["wordpress"]:
            r = sess.get(urljoin(root, "feed/"))
            m = _FEED_GEN_RE.search(r.text) if r is not None and r.status == 200 else None
            if m:
                fp["wordpress"] = m.group(1)
        for slug in [s for s, v in fp["plugins"].items() if not v][:MAX_README_FETCHES]:
            r = sess.get(urljoin(root, f"wp-content/plugins/{slug}/readme.txt"))
            m = _STABLE_TAG_RE.search(r.text) if r is not None and r.status == 200 else None
            if m:
                fp["plugins"][slug] = m.group(1)
        r = sess.get(urljoin(root, "wp-content/uploads/"))
        if r is not None and r.status == 200 and "Index of" in r.text and not same_as_catch_all(
                r, "wp-content/uploads/", lambda x: "Index of" in x.text):
            findings.append(_f("dir-listing-uploads", "exposure", "medium", "Directory listing on uploads",
                               "'Index of' listing on /wp-content/uploads/", urljoin(root, "wp-content/uploads/"),
                               "Disable autoindex (Options -Indexes)."))


def is_public_host(host) -> bool:
    """True when every address `host` resolves to is a public internet address.

    A hosted service that probes on a user's behalf must call this first:
    without it, "probe http://169.254.169.254/" or an internal hostname turns
    the service into a way to reach its own network (SSRF). The CLI does not
    need it; scanning your own LAN from your own machine is legitimate."""
    import ipaddress
    import socket
    host = (host or "").strip("[]").split("%")[0]
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return False
    addrs = {i[4][0].split("%")[0] for i in infos}
    try:
        return bool(addrs) and all(ipaddress.ip_address(a).is_global for a in addrs)
    except ValueError:
        return False


def local_token(host, home=None) -> str:
    """The CLI's ownership token for `host`: derived from a random secret kept
    in ~/.phpwarden/probe-secret (created on first use, mode 0600)."""
    import os
    import secrets
    from pathlib import Path
    d = Path(home or os.environ.get("PHPWARDEN_HOME") or Path.home() / ".phpwarden")
    f = d / "probe-secret"
    try:
        secret = f.read_text().strip()
    except OSError:
        secret = ""
    if len(secret) < 32:
        secret = secrets.token_hex(32)
        d.mkdir(parents=True, exist_ok=True)
        f.write_text(secret + "\n")
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    return generate_token(host, secret)


def run_probe(url, *, token=None, active=None, feed=None, max_requests=60, delay=0.3,
              fetch=None, tls_check=None):
    """Probe `url`. active=None: active if ownership verifies; active=True: require
    verification (refused otherwise); active=False: passive only."""
    if "://" not in url:
        url = "https://" + url
    p = urlsplit(url)
    root = f"{p.scheme}://{p.netloc}/"
    if feed is None:
        from .feed import FeedManager
        feed = FeedManager().current()
    sess = _Session(url, fetch, max_requests, delay)
    fp = {"php": None, "wordpress": None, "plugins": {}, "themes": {}, "frameworks": []}
    findings, ownership, mode = [], {"verified": False, "method": None}, "passive"
    incomplete = False

    try:
        # Passive: the single homepage GET, redirects NOT followed.
        home = sess.get(url, follow=False)
        if home is None:
            raise BudgetExceeded("homepage unreachable")
        findings += _header_findings(home, url)
        _fingerprint_headers(home, fp)
        _fingerprint_html(home.text, fp)
        tf, days = _tls_findings(url, tls_check or tls_days_left)
        findings += tf
        if days is not None:
            fp["tls_days_left"] = days

        if active is not False and token:
            ok, method = verify_ownership(url, token, homepage_html=home.text, _session=sess)
            ownership = {"verified": ok, "method": method}
            if ok:
                mode = "active"
                # Same-host redirect on homepage (e.g. / -> /home/) for HTML fingerprint.
                if home.status in (301, 302, 303, 307, 308):
                    h2 = sess.get(url)
                    if h2 is not None:
                        _fingerprint_html(h2.text, fp)
                _run_active(sess, root, fp, feed, findings)
        if active and not ownership["verified"]:
            sess.notes.append("active mode refused: ownership not verified")
    except BudgetExceeded as e:
        sess.notes.append(str(e))
        incomplete = mode == "active"     # the active checks were cut short

    findings += _vuln_findings(fp, feed, url)
    # de-duplicate by id
    seen, uniq = set(), []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            uniq.append(f)
    findings = rank(uniq)
    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    summary["exploited"] = sum(1 for f in findings if f.get("known_exploited"))
    summary["total"] = len(findings)
    return {"tool": "phpwarden-probe", "version": __version__, "target": url, "mode": mode,
            "ownership": ownership, "requests_made": sess.count, "fingerprint": fp,
            "findings": findings, "summary": summary, "notes": sess.notes,
            # False when the request or time budget ran out before every check ran:
            # "nothing found" on an incomplete run is not a clean result.
            "complete": not incomplete,
            "feed_version": getattr(feed, "feed_version", None)}


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def to_text(result):
    fp = result["fingerprint"]
    lines = [f"phpwarden probe {result['version']} -- {result['target']}",
             f"mode: {result['mode']}  ownership: "
             + (f"verified ({result['ownership']['method']})" if result["ownership"]["verified"] else "not verified")
             + f"  requests: {result['requests_made']}"]
    bits = []
    if fp.get("php"):
        bits.append(f"PHP {fp['php']}")
    if fp.get("wordpress"):
        bits.append(f"WordPress {fp['wordpress']}")
    if fp.get("plugins"):
        bits.append(f"{len(fp['plugins'])} plugins")
    if fp.get("frameworks"):
        bits.append("frameworks: " + ", ".join(fp["frameworks"]))
    if bits:
        lines.append("fingerprint: " + "; ".join(bits))
    lines.append("")
    # A version header such as "X-Powered-By: PHP/8.1.2" can match dozens of
    # engine CVEs, most only "possibly" (SAPI and OS are invisible from
    # outside). Exploited ones are listed; the rest collapse into one line.
    # JSON and SARIF keep every finding.
    engine_rest = [f for f in result["findings"] if str(f.get("id", "")).endswith("-php")
                   and f.get("kind") == "vuln" and not f.get("known_exploited")]
    skip = {id(f) for f in engine_rest} if len(engine_rest) > 3 else set()
    for f in result["findings"]:
        if id(f) in skip:
            continue
        mark = "[EXPLOITED] " if f.get("known_exploited") else ""
        cve = f" {f['cve']}" if f.get("cve") else ""
        lines.append(f"  {f['severity'].upper():<8} {mark}{f['title']}{cve} -- {f['evidence']}")
    if skip:
        worst = min(engine_rest, key=lambda f: SEV_ORDER.get(f["severity"], 9))["severity"]
        sure = sum(1 for f in engine_rest if "(possibly)" not in f["title"])
        lines.append(f"  {worst.upper():<8} PHP {fp.get('php')}: {len(engine_rest)} more engine CVEs match this version "
                     f"({sure} certain, {len(engine_rest) - sure} depend on the server setup). "
                     f"Run `phpwarden scan` on the server for exact verdicts, or use --json for the list.")
    if not result["findings"]:
        lines.append("  no findings")
    s = result["summary"]
    lines += ["", "summary: " + ", ".join(f"{s[k]} {k}" for k in SEV_ORDER if s.get(k))
              + f"; {s['exploited']} known exploited"]
    if result.get("complete") is False:
        lines.append("INCOMPLETE: the request or time budget ran out before every check ran "
                     "(a site that redirects everything can cause this). Raise --max-requests and rerun.")
    if result["mode"] == "passive":
        lines.append("passive mode: verify ownership to run active checks (see https://phpwarden.io/probe)")
    return "\n".join(lines)


def to_sarif(result):
    rules, seen = [], set()
    results = []
    for f in result["findings"]:
        if f["id"] not in seen:
            seen.add(f["id"])
            rule = {"id": f["id"], "shortDescription": {"text": f["title"]},
                    "properties": {"kind": f["kind"], "severity": f["severity"]}}
            if f.get("fix"):
                rule["help"] = {"text": f["fix"]}
            rules.append(rule)
        props = {"severity": f["severity"], "known_exploited": bool(f.get("known_exploited"))}
        if f.get("cve"):
            props["cve"] = f["cve"]
        if f.get("epss") is not None:
            props["epss"] = f["epss"]
        results.append({"ruleId": f["id"], "level": _SARIF_LEVEL.get(f["severity"], "note"),
                        "message": {"text": f"{f['title']}: {f['evidence']}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["url"]}}}],
                        "properties": props})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "phpwarden-probe", "version": result["version"],
                                          "informationUri": "https://phpwarden.io/probe", "rules": rules}},
                      "results": results}]}


def exit_code(result):
    """1 if any finding is high/critical or known exploited, else 0."""
    return 1 if any(SEV_ORDER.get(f["severity"], 9) <= 1 or f.get("known_exploited")
                    for f in result["findings"]) else 0
