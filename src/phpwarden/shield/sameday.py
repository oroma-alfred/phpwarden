"""Same-day virtual patches: draft, verify and review a Shield rule for a CVE
that has just been added to CISA KEV.

    entry  = draft_rule("CVE-2026-1234", feed, hints=None)   # "draft, unverified"
    result = verify(entry)                                    # benign replay
    q = Queue(dir); q.add(entry, result)                      # review queue
    q.approve("CVE-2026-1234", by="Oroma")                    # -> shield-sameday.json

Drafting works from the advisory in the feed (component, affected range,
title) plus optional human-written hints (endpoint, parameter, vulnerability
class) taken from the advisory or a public write-up. Nothing is fetched or run
from a PoC: hints are a request *shape*, and the positive examples are benign
markers ("../../wp-config.php", "probe.php", "1' UNION SELECT NULL-- -") that
trip the rule without doing anything on a real site.

Verification replays the rule's positive examples (must match), its negative
examples and a corpus of ordinary WordPress / Laravel / API traffic (must not
match) through the Python matcher, and through the real PHP agent under
`php -S` when PHP is installed. Only a rule that passes can be approved, only a
human approves, and an approved rule still reaches every site in log mode.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import http.client
from pathlib import Path

from phpwarden.shield import matcher
from phpwarden.shield.library import FORM, JSON, R

DATA = Path(__file__).resolve().parent.parent / "data" / "shield-sameday.json"
NEW_DAYS = 14
DRAFT, VERIFIED, APPROVED, REJECTED = "draft, unverified", "draft, verified", "approved", "rejected"

# --------------------------------------------------------------- classes
# value regex (case-insensitive, Python re and PCRE), benign attack-shape
# values, ordinary values for the same parameter.
CLASSES = {
    "sqli": {
        "words": ("sql injection", "sqli", "sql query"),
        "re": r"(?:'|\x22|\))\s*(?:or|and|union|order\s+by|group\s+by|;)\s|union(?:\s|/\*.*?\*/)+(?:all\s+)?select|"
              r"\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml)\s*\(|\bwaitfor\s+delay\b",
        "pos": ["1' UNION SELECT NULL-- -", "1) AND SLEEP(0)-- -", "x\" OR \"1\"=\"1"],
        "neg": ["O'Brien", "rock 'n' roll", "42", "select a plan", "sleep well"],
    },
    "traversal": {
        "words": ("path traversal", "directory traversal", "local file inclusion", "file inclusion", "lfi",
                  "arbitrary file read", "arbitrary file download", "arbitrary file deletion"),
        "re": r"(?:\.\.|%2e%2e)(?:/|\\|%2f|%5c)|^\s*(?:/etc/|/proc/|[a-z]:\\\\windows)|^\s*(?:php|phar|zip|expect|file)://",
        "pos": ["../../wp-config.php", "..%2f..%2fetc%2fpasswd", "php://filter/resource=index"],
        "neg": ["report-2026.pdf", "images/logo.png", "a..b", "docs/guide.html"],
    },
    "upload": {
        "words": ("file upload", "arbitrary file upload", "unrestricted upload", "upload"),
        "location": "file_name",
        "re": r"\.(?:php[0-9s]?|phtml|phar|pht|pgif|inc)(?:$|\.|\s|%00|\x00)|^\.ht",
        "pos": ["probe.php", "probe.php.jpg", "probe.phtml", ".htaccess"],
        "neg": ["photo.jpg", "cv.pdf", "phpinfo-notes.txt", "logo.png"],
    },
    "deserialization": {
        "words": ("deserialization", "deserialisation", "object injection", "unserialize"),
        "re": r"(?:^|[;{}:\x22])[oc]:\d{1,4}:\x22[a-z_\\][a-z0-9_\\]{2,200}\x22:\d{1,4}:\{",
        "pos": ['O:8:"stdClass":0:{}', 'a:1:{i:0;O:5:"Probe":0:{}}'],
        "neg": ['a:1:{i:0;s:3:"abc";}', "O:24 hours", "{\"o\":1}"],
    },
    "code": {
        "words": ("code injection", "remote code execution", "code execution", "rce", "eval", "php object", "template injection"),
        "re": r"<\?(?:php|=)|\b(?:system|exec|passthru|shell_exec|popen|proc_open|assert|eval|create_function|"
              r"call_user_func(?:_array)?|base64_decode|file_put_contents)\s*\(|\$\{[^}]{0,40}\}|\{\{.{0,40}\}\}",
        "pos": ["<?php echo 1;", "system(\"true\")", "{{7*7}}"],
        "neg": ["the eval team", "systems (internal)", "price ${ amount", "hello"],
    },
    "command": {
        "words": ("command injection", "os command", "shell command"),
        "re": r"(?:[;|`&\n]|\$\()\s*(?:id|whoami|uname|curl|wget|sh|bash|nc|ping|nslookup|cat|echo)\b",
        "pos": ["x;id", "a|whoami", "$(true)", "`uname`"],
        "neg": ["Tom & Jerry", "a; b", "size: 10|20", "ping pong"],
    },
    "ssrf": {
        "words": ("server-side request forgery", "ssrf"),
        "re": r"^\s*(?:gopher|dict|file|ftp|ldap|php)://|169\.254\.169\.254|metadata\.google|"
              r"^\s*https?://(?:localhost|127\.|0\.0\.0\.0|\[?::1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)",
        "pos": ["http://169.254.169.254/latest/meta-data/", "gopher://127.0.0.1:6379/_", "http://127.0.0.1:8080/"],
        "neg": ["https://example.com/feed.xml", "https://cdn.example.org/a.png"],
    },
    "xxe": {
        "words": ("xxe", "xml external entit"),
        "location": "body",
        "re": r"<!(?:doctype|entity)[^>]{0,200}(?:system|public|%)",
        "pos": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "http://127.0.0.1/">]><r>&e;</r>'],
        "neg": ['<?xml version="1.0"?><r><a>1</a></r>'],
    },
    "xss": {
        "words": ("cross-site scripting", "xss"),
        "re": r"<\s*(?:script|svg|iframe|img|body|details)\b[^>]*(?:>|\bon[a-z]+\s*=)|\bon(?:error|load|mouseover|focus|toggle)\s*=|"
              r"javascript\s*:",
        "pos": ["<script>probe()</script>", "<img src=x onerror=probe()>", "javascript:probe()"],
        "neg": ["I <3 PHP", "a < b > c", "online=yes", "Script writing 101"],
    },
}
# "presence": the parameter itself is the attack shape (a field ordinary clients
# of this endpoint never send). Only from hints, and the hint must name it.
CLASSES["presence"] = {"words": (), "re": None, "pos": ["1"], "neg": []}
NO_SHAPE = ("privilege escalation", "authentication bypass", "auth bypass", "missing authorization", "use-after-free",
            "type confusion", "memory corruption", "overflow", "csrf", "weak hash", "information disclosure")


MEMORY = ("use-after-free", "type confusion", "memory corruption", "overflow", "memory disclosure", "double free")
ORDER = ("upload", "deserialization", "sqli", "xxe", "ssrf", "command", "traversal", "code", "xss")


def classify(text):
    """Vulnerability class from advisory text, or None. Memory-safety bugs come
    first: their trigger is not a value a rule can recognise."""
    t = (text or "").lower()
    if any(w in t for w in MEMORY):
        return None
    for k in ORDER:
        if any(re.search(r"\b" + re.escape(w) + r"\b", t) for w in CLASSES[k]["words"]):
            return k
    return None


# --------------------------------------------------------------- advisory

def advisory_for(feed, cve):
    """The feed's record(s) for a CVE as one dict: target, title, affected."""
    for a in getattr(feed, "wp", []):
        if a.cve == cve:
            t = {"plugin": "wp-plugin", "theme": "wp-theme", "core": "wp-core"}.get(a.type, "wp-plugin")
            target = {"type": t} if t == "wp-core" else {"type": t, "slug": a.slug}
            return {"cve": cve, "target": target, "title": a.title, "affected": a.affected,
                    "fixed": list(a.fixed), "kev": a.known_exploited, "refs": list(a.references)}
    for a in getattr(feed, "composer", []):
        if a.cve == cve:
            return {"cve": cve, "target": {"type": "composer", "package": a.package}, "title": a.title,
                    "affected": a.affected, "fixed": list(a.fixed), "kev": a.known_exploited, "refs": list(a.references)}
    c = feed.by_id(cve) if hasattr(feed, "by_id") else None
    if c:
        sapi = next((s for s in c.sapi if s not in ("any", "")), None)
        return {"cve": cve, "target": {"type": "engine", **({"sapi": sapi} if sapi else {})},
                "title": f"{c.title} ({c.cls})", "affected": "", "fixed": [b.get("fixed") for b in c.branches.values()
                                                                           if isinstance(b, dict) and b.get("fixed")],
                "kev": c.exploited_in_wild, "refs": list(c.references)}
    return None


_PATH_RX = re.compile(r"(/(?:wp-json|wp-admin|wp-content|_[a-z]+|api|index\.php)[A-Za-z0-9_\-./{}]*|/[A-Za-z0-9_\-./]+\.php)")
_ACTION_RX = re.compile(r"(?:action=|[`'\x22]([a-z0-9_]+)[`'\x22]\s+(?:ajax\s+)?action|ajax action [`'\x22]?)([a-z0-9_]+)?", re.I)
_PARAM_RX = re.compile(r"[`'\x22]([A-Za-z0-9_\[\]-]{1,60})[`'\x22]\s+(?:parameter|param|field|argument|header)|"
                       r"(?:parameter|param|field|argument)\s+[`'\x22]?([A-Za-z0-9_\[\]-]{1,60})", re.I)


def extract_hints(text):
    """Endpoint, AJAX action and parameter named in advisory or write-up text."""
    out = {}
    m = _PATH_RX.search(text or "")
    if m:
        out["path"] = m.group(1).rstrip(".")
    m = _ACTION_RX.search(text or "")
    if m and (m.group(1) or m.group(2)):
        out["action"] = m.group(1) or m.group(2)
    m = _PARAM_RX.search(text or "")
    if m:
        p = m.group(1) or m.group(2)
        if p.lower() not in ("the", "a", "an", "in", "via", "of"):
            out["param"] = p
    return out


def _param_name(p):
    """'upload[]' and 'files[0]' are the PHP parameter 'upload' / 'files'."""
    return re.sub(r"\[[^\]]*\]$", "", p or "") or p


def _slug_id(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:50]


def _scope_path(target, hints):
    if hints.get("path"):
        p = hints["path"].split("?", 1)[0]
        return re.escape(p).replace(r"\{", "{").replace(r"\}", "}").replace("{id}", r"[^/]+")
    if target["type"] in ("wp-plugin", "wp-theme"):
        s = re.escape(target["slug"].lower())
        kind = "plugins" if target["type"] == "wp-plugin" else "themes"
        return rf"/wp-content/{kind}/{s}/|/wp-json/{s}\b|/wp-admin/admin-(?:ajax|post)\.php"
    return None


def draft_rule(cve, feed=None, hints=None, advisory=None):
    """A candidate library entry (status "draft, unverified"), or a stub with
    "rule": None and the reason when no request shape can be drafted."""
    adv = advisory or (advisory_for(feed, cve) if feed is not None else None)
    hints = dict(hints or {})
    if hints.get("param"):
        hints["param"] = _param_name(hints["param"])
    if adv is None:
        return {"cve": cve, "rule": None, "status": DRAFT, "reason": "CVE is not in the feed", "hints": hints}
    text = " ".join([adv.get("title", ""), hints.get("notes", "")])
    for k, v in extract_hints(text).items():
        hints.setdefault(k, _param_name(v) if k == "param" else v)
    cls = hints.get("class") or classify(text)
    target = adv["target"]
    comp = target.get("slug") or target.get("package") or target.get("sapi") or target["type"]
    base = {"cve": cve, "status": DRAFT, "advisory": adv, "hints": hints, "class": cls, "drafted": int(time.time())}
    if cls not in CLASSES:
        why = next((w for w in NO_SHAPE if w in text.lower()), None)
        return {**base, "rule": None,
                "reason": (f"'{why}' has no request shape a rule can match without the vulnerable endpoint and parameter"
                           if why else "vulnerability class not recognised") +
                          "; add hints (path, param, class) from the advisory or a public write-up and draft again"}
    c = CLASSES[cls]
    if cls == "presence" and not hints.get("param"):
        return {**base, "rule": None, "reason": "class 'presence' needs the parameter name in the hints"}
    loc = hints.get("location") or c.get("location") or "param"
    path = _scope_path(target, hints)
    conds = []
    if hints.get("action"):
        conds.append({"in": "param", "name": "action", "re": "^" + re.escape(hints["action"]) + "$"})
    if cls == "presence":
        conds.append({"in": "param_name", "re": "^" + re.escape(hints["param"]) + "$"})
    elif loc == "param":
        conds.append({"in": "param", "name": hints.get("param") or "*", "re": c["re"]})
    elif loc == "header":
        conds.append({"in": "header", "name": hints.get("param") or "", "re": c["re"]})
    else:
        conds.append({"in": loc, "re": c["re"]})
    entry = {"id": _slug_id(f"{comp}-{cls}-{cve}"), "cve": cve, "target": target,
             "description": f"Same-day draft for {cve}: {adv.get('title', '')}".strip()[:300],
             "refs": (adv.get("refs") or [])[:4] or [f"https://nvd.nist.gov/vuln/detail/{cve}"],
             **({"affected": adv["affected"]} if adv.get("affected") else {}),
             **({"fixed": [x for x in adv["fixed"] if x][:6]} if adv.get("fixed") else {}),
             **({"method": [m.upper() for m in hints["method"]]} if hints.get("method") else {}),
             **({"path": path} if path else {}), "all": conds}
    entry["pos"], entry["neg"] = _examples(entry, hints, c, loc)
    confidence = "high" if path and (hints.get("param") or loc != "param") else "medium" if path else "low"
    return {**base, "rule": entry, "confidence": confidence, "reason": ""}


def _examples(entry, hints, c, loc):
    """Benign attack-shape requests (pos) and ordinary ones (neg) on the rule's endpoint."""
    if hints.get("path"):
        uri = hints["path"].split("?", 1)[0].replace("{id}", "1")
    elif entry["target"]["type"] in ("wp-plugin", "wp-theme"):
        uri = "/wp-admin/admin-ajax.php"
    else:
        uri = "/index.php"
    method = (entry.get("method") or ["POST"])[0]
    param = hints.get("param") or "q"
    extra = {"action": hints["action"]} if hints.get("action") else {}
    from urllib.parse import urlencode

    def req(value):
        if loc == "file_name":
            return R("POST", uri, body=urlencode(extra), ctype="multipart/form-data", files=[(param or "file", value)])
        if loc == "body":
            return R("POST", uri, body=value, ctype="application/xml")
        if loc == "header":
            return R(method, uri, headers={param: value})
        body = urlencode({**extra, param: value})
        return R("GET", uri + "?" + body) if method == "GET" else R(method, uri, body=body, ctype=FORM)
    if not c["re"]:                                 # presence: neg = same endpoint, ordinary field
        pos = [req(v) for v in c["pos"]]
        param = "page"                              # req() reads `param` when called
        return pos, [req("1")]
    return [req(v) for v in c["pos"]], [req(v) for v in c["neg"]]


# --------------------------------------------------------------- verification
# Representative legitimate traffic. A same-day rule must match none of it.
BENIGN = [
    R(uri="/"), R(uri="/?s=O%27Brien+%26+sons"), R(uri="/blog/2026/11/hello-world/"),
    R(uri="/?p=123&preview=true"), R(uri="/category/news/page/2/"), R(uri="/wp-json/wp/v2/posts?per_page=10"),
    R("POST", "/wp-admin/admin-ajax.php", body="action=heartbeat&_nonce=a1b2c3&data%5Bwp-auth-check%5D=true", ctype=FORM),
    R("POST", "/wp-admin/admin-ajax.php", body="action=woocommerce_add_to_cart&product_id=42&quantity=1", ctype=FORM),
    R("POST", "/wp-login.php", body="log=anna&pwd=correct+horse&redirect_to=%2Fwp-admin%2F", ctype=FORM),
    R("POST", "/wp-comments-post.php", body="comment=Great+post%21+I+%3C3+PHP%2C+and+O%27Brien+agrees.&author=Ann&email=ann%40example.com", ctype=FORM),
    R("POST", "/wp-admin/async-upload.php", body="name=photo.jpg&action=upload-attachment", ctype="multipart/form-data",
      files=[("async-upload", "photo.jpg")]),
    R("POST", "/wp-admin/post.php", body="post_title=Release+notes&content=%3Cp%3EHello+%3Cstrong%3Eworld%3C%2Fstrong%3E%3C%2Fp%3E&action=editpost", ctype=FORM),
    R(uri="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9"),
    R(uri="/wp-content/uploads/2026/11/logo.png"),
    R("POST", "/wp-json/contact-form-7/v1/contact-forms/12/feedback", body="your-name=Ann&your-message=Call+me+at+10%3A30", ctype=FORM),
    R(uri="/shop/?orderby=price&order=desc&min_price=10"),
    R("POST", "/login", body="_token=abc&email=ann%40example.com&password=s3cret", ctype=FORM),
    R("POST", "/api/orders", body='{"items":[{"sku":"A-1","qty":2}],"note":"leave at door"}', ctype=JSON),
    R("PUT", "/api/users/7", body='{"name":"Ann O\'Brien","bio":"Systems engineer; likes 1|2 splits"}', ctype=JSON),
    R(uri="/search?q=union+select+meeting+agenda"), R(uri="/search?q=how+to+use+..%2Fparent+paths"),
    R(uri="/docs/getting-started.html"), R(uri="/index.php?route=product/product&product_id=50"),
    R("POST", "/graphql", headers={"Store": "default"}, body='{"query":"{ products { items { sku } } }"}', ctype=JSON),
    R(uri="/feed/", headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"}),
    R(uri="/", cookies={"wordpress_logged_in_abc": "anna%7C1700000000%7Ctoken", "woocommerce_cart_hash": "e3b0c442"}),
    R("POST", "/xmlrpc.php", body="<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName></methodCall>",
      ctype="text/xml"),
    R(uri="/redirect?to=https%3A%2F%2Fexample.com%2Fthanks"),
    R("POST", "/newsletter", body="email=ann%2Btag%40example.com&list=weekly", ctype=FORM),
]

_BAD_PCRE = [(re.compile(r"[*+?}]\+"), "possessive quantifier"), (re.compile(r"~"), "'~' (PHP delimiter)"),
             (re.compile(r"\(\?<[=!][^)]*[*+{]"), "variable-length look-behind")]


def lint(entry):
    """Problems that make a rule unsafe to ship, as strings."""
    out = []
    regs = ([entry["path"]] if entry.get("path") else []) + [c["re"] for c in entry.get("all", []) if c.get("re")]
    for rx in regs:
        try:
            re.compile(rx, re.I | re.S)
        except re.error as e:
            out.append(f"regex does not compile: {e}")
        for bad, why in _BAD_PCRE:
            if bad.search(rx):
                out.append(f"not PCRE-portable: {why} in {rx[:60]}")
    if entry["target"]["type"] != "generic" and not entry.get("path") and not any(
            c.get("name") not in (None, "*") or c["in"] in ("header", "file_name", "param_name") for c in entry.get("all", [])):
        out.append("not scoped: no path and no named parameter, so it would inspect every request on the site")
    if not entry.get("pos") or not entry.get("neg"):
        out.append("needs at least one attack-shape (pos) and one ordinary (neg) example")
    return out


def verify(entry_or_draft, extra_benign=(), agent=True):
    """{"passed", "lint", "misses", "false_positives", "agent", "checked"}"""
    e = entry_or_draft.get("rule", entry_or_draft) if "rule" in entry_or_draft else entry_or_draft
    if not e:
        return {"passed": False, "lint": ["no rule drafted"], "misses": [], "false_positives": [], "agent": "skipped",
                "checked": 0}
    res = {"lint": lint(e), "misses": [], "false_positives": [], "agent": "skipped"}
    benign = list(e.get("neg", [])) + BENIGN + list(extra_benign)
    if not any("compile" in x for x in res["lint"]):
        res["misses"] = [r["uri"] for r in e.get("pos", []) if not matcher.match_rule(e, r)]
        res["false_positives"] = [f'{r["method"]} {r["uri"]}' for r in benign if matcher.match_rule(e, r)]
        if agent:
            res["agent"] = _agent_replay(e, benign, res)
    res["checked"] = len(e.get("pos", [])) + len(benign)
    res["passed"] = not (res["lint"] or res["misses"] or res["false_positives"]) and res["agent"] in ("ok", "skipped")
    return res


AGENT = Path(__file__).resolve().parent / "agent" / "phpwarden-shield.php"
ROUTER = '<?php header("Content-Type: text/plain"); echo "ok";\n'


def _agent_replay(e, benign, res):
    """Replay through the real agent (php -S, log mode then block mode). Returns
    "ok", "skipped" (no PHP) or "failed" (details appended to res)."""
    php = shutil.which("php")
    if not php or not AGENT.is_file():
        return "skipped"
    tmp = Path(tempfile.mkdtemp(prefix="pw-sameday-"))
    try:
        (tmp / "router.php").write_text(ROUTER)
        shutil.copy(AGENT, tmp / "phpwarden-shield.php")
        logf = tmp / "shield.log"
        rule = {"id": e["id"], "cve": e.get("cve"), "mode": "log", **({"method": e["method"]} if e.get("method") else {}),
                **({"path": e["path"]} if e.get("path") else {}), "all": e.get("all", [])}
        failed = False
        for mode in ("log", "block"):
            pol = {"version": 1, "mode": "enforce" if mode == "block" else "log", "budget_ms": 50,
                   "log": {"path": str(logf), "max_bytes": 5_000_000}, "rules": [dict(rule, mode=mode)]}
            (tmp / "policy.json").write_text(json.dumps(pol))
            s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            proc = subprocess.Popen([php, "-d", f"auto_prepend_file={tmp / 'phpwarden-shield.php'}", "-S",
                                     f"127.0.0.1:{port}", str(tmp / "router.php")],
                                    env=dict(os.environ, PHPWARDEN_SHIELD_POLICY=str(tmp / "policy.json")),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
                    except OSError:
                        time.sleep(0.05)
                for r in e.get("pos", []):
                    logf.unlink(missing_ok=True)
                    st = _send(port, r)
                    hit = logf.exists() and e["id"] in logf.read_text()
                    want = 403 if mode == "block" else 200
                    if st != want or not hit:
                        res["misses"].append(f"agent {mode} mode: {r['uri']} -> {st}, logged={hit}")
                        failed = True
                if mode == "log":
                    for r in benign:
                        logf.unlink(missing_ok=True)
                        st = _send(port, r)
                        if st != 200 or (logf.exists() and e["id"] in logf.read_text()):
                            res["false_positives"].append(f"agent: {r['method']} {r['uri']}")
                            failed = True
            finally:
                proc.terminate(); proc.wait(5)
        return "failed" if failed else "ok"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _send(port, req):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = dict(req.get("headers") or {})
    if req.get("cookies"):
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in req["cookies"].items())
    body, ctype = matcher.wire(req)
    if body:
        h["Content-Type"] = ctype
    c.putrequest(req.get("method", "GET"), req["uri"].replace(" ", "%20"), skip_accept_encoding=True)
    for k, v in h.items():
        c.putheader(k, v)
    if body:
        c.putheader("Content-Length", str(len(body)))
    c.endheaders(body or None)
    r = c.getresponse(); r.read(); c.close()
    return r.status


# --------------------------------------------------------------- review queue

class Queue:
    """One JSON file per CVE: the draft, its verification and its review."""

    def __init__(self, path=None, rules_file=None):
        self.dir = Path(path or os.environ.get("PHPWARDEN_VPATCH_QUEUE") or Path.home() / ".phpwarden" / "vpatch-queue")
        self.rules_file = Path(rules_file or DATA)

    def _f(self, cve):
        if not re.match(r"^CVE-\d{4}-\d{3,8}$", cve or ""):
            raise ValueError("bad CVE id")
        return self.dir / f"{cve}.json"

    def add(self, draft, verification):
        self.dir.mkdir(parents=True, exist_ok=True)
        status = VERIFIED if verification.get("passed") else DRAFT
        doc = {**draft, "status": status, "verification": verification, "review": None, "updated": int(time.time())}
        self._f(draft["cve"]).write_text(json.dumps(doc, indent=1))
        return doc

    def get(self, cve):
        f = self._f(cve)
        return json.loads(f.read_text()) if f.exists() else None

    def list(self, status=None):
        if not self.dir.is_dir():
            return []
        docs = [json.loads(p.read_text()) for p in sorted(self.dir.glob("CVE-*.json"))]
        return [d for d in docs if status is None or d["status"] == status]

    def reject(self, cve, by, why=""):
        doc = self.get(cve) or {}
        if not doc:
            raise KeyError(cve)
        doc.update(status=REJECTED, review={"by": by, "at": int(time.time()), "decision": "rejected", "why": why})
        self._f(cve).write_text(json.dumps(doc, indent=1))
        return doc

    def approve(self, cve, by, rule=None):
        """Re-verify, then add the rule to the shipped same-day rule set. `rule`
        replaces the draft (after a human edit); it is verified the same way."""
        if not (by or "").strip():
            raise ValueError("a named reviewer is required")
        doc = self.get(cve)
        if not doc:
            raise KeyError(cve)
        entry = rule or doc.get("rule")
        v = verify(entry or {"rule": None})
        if not v["passed"]:
            doc.update(verification=v, status=DRAFT)
            self._f(cve).write_text(json.dumps(doc, indent=1))
            raise ValueError("verification failed: " + "; ".join(v["lint"] + v["misses"] + v["false_positives"])[:500])
        now = int(time.time())
        entry = {**entry, "sameday": {"approved_at": now, "approved_by": by.strip(), "verified_at": now,
                                      "checked": v["checked"], "agent": v["agent"]}}
        rules = [r for r in load_rules(self.rules_file) if r["id"] != entry["id"]] + [entry]
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)
        self.rules_file.write_text(json.dumps({"rules": rules}, indent=1) + "\n")
        doc.update(status=APPROVED, rule=entry, verification=v,
                   review={"by": by.strip(), "at": now, "decision": "approved"})
        self._f(cve).write_text(json.dumps(doc, indent=1))
        return doc


def load_rules(path=None):
    """Approved same-day rules (library entry format plus "sameday")."""
    p = Path(path or os.environ.get("PHPWARDEN_SAMEDAY_RULES") or DATA)
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError):
        return []
    return [r for r in doc.get("rules", []) if isinstance(r, dict) and r.get("id") and (r.get("sameday") or {}).get("approved_by")]


def is_new(entry, now=None):
    at = (entry.get("sameday") or {}).get("approved_at")
    return bool(at) and (int(now or time.time()) - int(at)) < NEW_DAYS * 86400


# --------------------------------------------------------------- email

def review_email(doc):
    """(subject, body) for the review email to sales@."""
    cve, v, rule = doc["cve"], doc.get("verification") or {}, doc.get("rule")
    head = f"[phpwarden] Shield draft for {cve}: {doc['status']}"
    lines = [f"A same-day Shield rule was drafted for {cve}, newly on CISA KEV.",
             (doc.get("advisory") or {}).get("title", ""), "",
             f"Status: {doc['status']}. Nothing ships until you approve it, and an approved rule only logs until each "
             f"site owner switches it to block.", ""]
    if not rule:
        lines += ["No rule could be drafted: " + doc.get("reason", ""), "",
                  f"To retry with hints: python3 scripts/vpatch.py draft {cve} --hints hints.json"]
        return head, "\n".join(lines)
    lines += [f"Confidence: {doc.get('confidence')} (class {doc.get('class')}, component "
              f"{rule['target'].get('slug') or rule['target'].get('package') or rule['target']['type']})",
              f"Verification: {'PASSED' if v.get('passed') else 'FAILED'}; {v.get('checked', 0)} requests checked, "
              f"real PHP agent {v.get('agent')}."]
    for k in ("lint", "misses", "false_positives"):
        for x in v.get(k, [])[:10]:
            lines.append(f"  {k}: {x}")
    lines += ["", "--- Rule ---", json.dumps({k: rule[k] for k in rule if k not in ("pos", "neg")}, indent=1), "",
              "--- Attack-shape examples (benign markers, not exploits) ---"]
    lines += [f"  {r['method']} {r['uri']} {r.get('body', '')[:120]}" for r in rule.get("pos", [])]
    lines += ["", "Review: check the endpoint and parameter against the advisory, and that ordinary use of the "
                  "component would not send these values.",
              f"Approve: python3 scripts/vpatch.py approve {cve} --by Oroma",
              f"Reject:  python3 scripts/vpatch.py reject {cve} --by Oroma --why '...'"]
    return head, "\n".join(lines)
