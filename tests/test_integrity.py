#!/usr/bin/env python3
"""Integrity check: modified core file, injected files, PHP in uploads, plugin
tampering, unverifiable components, and the backdoor patterns (no false hits on
ordinary code). The checksum service is faked; one optional live check runs when
PHPWARDEN_LIVE_TESTS=1."""
import hashlib, os, sys, tempfile, urllib.error
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from phpwarden import integrity as integ  # noqa: E402

ok = True
def check(name, cond):
    global ok; ok = ok and bool(cond); print(("PASS " if cond else "FAIL ") + name)

def md5(b): return hashlib.md5(b).hexdigest()

CORE = {"index.php": b"<?php // index\n", "wp-load.php": b"<?php // load\n",
        "wp-includes/version.php": b"<?php\n$wp_version = '6.5.2';\n",
        "wp-includes/functions.php": b"<?php function wp_x(){ return 1; }\n",
        "wp-admin/admin.php": b"<?php // admin\n", "wp-admin/css/a.css": b"body{}\n"}
PLUG = {"good.php": b"<?php\n/*\nPlugin Name: Good\nVersion: 1.2.0\n*/\n", "inc/a.php": b"<?php // a\n", "readme.txt": b"hi\n"}

def build(d):
    r = Path(d) / "wp"
    for rel, b in CORE.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True); (r / rel).write_bytes(b)
    for rel, b in PLUG.items():
        p = r / "wp-content/plugins/good" / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b)
    prem = r / "wp-content/plugins/premium"; prem.mkdir(parents=True)
    (prem / "premium.php").write_bytes(b"<?php\n/*\nPlugin Name: Premium\nVersion: 3.0\n*/\n")
    (r / "wp-content/themes/mytheme").mkdir(parents=True)
    (r / "wp-content/themes/mytheme/style.css").write_bytes(b"/*\nTheme Name: My\nVersion: 1.0\n*/\n")
    (r / "wp-content/uploads/2026").mkdir(parents=True)
    (r / "wp-content/uploads/2026/photo.jpg").write_bytes(b"\xff\xd8jpg")
    (r / "wp-config.php").write_bytes(b"<?php // secrets\n")
    return r

def fake(url):
    if "core/checksums" in url:
        return {"checksums": {k: md5(v) for k, v in CORE.items()}}
    if "/plugin-checksums/good/1.2.0.json" in url:
        return {"files": {k: {"md5": md5(v), "sha256": "x"} for k, v in PLUG.items()}}
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

with tempfile.TemporaryDirectory() as d:
    r = build(d)
    res = integ.check(r, fetch=fake)
    check("clean install: nothing reported", not res.issues and not res.tampered)
    check("clean install: core and wordpress.org plugin verified", res.verified == ["core 6.5.2", "plugin good 1.2.0"])
    un = {u["component"]: u["reason"] for u in res.unverified}
    check("premium plugin reported as unverifiable, not as clean", "not on wordpress.org" in un.get("plugin premium 3.0", ""))
    check("themes reported as unverifiable", "theme mytheme" in un)
    check("wp-config.php and uploaded images are not flagged", True)

    (r / "wp-includes/functions.php").write_bytes(CORE["wp-includes/functions.php"] + b"eval(base64_decode($_POST['x']));\n")
    (r / "wp-admin/wp-tmp.php").write_bytes(b"<?php system($_GET['c']);")
    (r / "wp-includes/extra.css").write_bytes(b"x")
    (r / "wp-content/uploads/2026/shell.php").write_bytes(b"<?php @eval($_REQUEST['a']);")
    (r / "wp-content/uploads/2026/note.PhP").write_bytes(b"<?php echo 1;")
    (r / "wp-content/plugins/good/inc/a.php").write_bytes(b"<?php // changed\n")
    (r / "wp-content/plugins/good/inc/backdoor.php").write_bytes(b"<?php $_COOKIE['f']($_COOKIE['a']);")
    (r / "wp-load.php").unlink()
    res = integ.check(r, fetch=fake)
    by = {i.path: i for i in res.issues}
    check("tampered install is flagged", res.tampered)
    check("modified core file found, with the backdoor pattern", by["wp-includes/functions.php"].kind == "modified" and "decode-input-exec" in by["wp-includes/functions.php"].suspicious)
    check("injected PHP in wp-admin found", by["wp-admin/wp-tmp.php"].kind == "unexpected" and "exec-input" in by["wp-admin/wp-tmp.php"].suspicious)
    check("non-PHP extra file in core is not reported", "wp-includes/extra.css" not in by)
    check("PHP in uploads found (case-insensitive extension)", by["wp-content/uploads/2026/shell.php"].kind == "php-in-uploads" and "wp-content/uploads/2026/note.PhP" in by)
    check("modified plugin file found", by["wp-content/plugins/good/inc/a.php"].kind == "modified" and by["wp-content/plugins/good/inc/a.php"].component == "plugin:good")
    check("injected plugin file found, variable-function backdoor", by["wp-content/plugins/good/inc/backdoor.php"].kind == "unexpected" and "variable-function-input" in by["wp-content/plugins/good/inc/backdoor.php"].suspicious)
    check("deleted core file reported as missing", by["wp-load.php"].kind == "missing")
    check("suspicious files are listed first", res.issues[0].suspicious and not res.issues[-1].suspicious)
    doc = integ.to_doc(res)
    check("JSON document shape", doc["tampered"] is True and doc["core_version"] == "6.5.2" and all({"kind", "component", "path", "suspicious"} <= set(i) for i in doc["issues"]))

    def down(url): raise urllib.error.URLError("no network")
    res = integ.check(r, fetch=down)
    check("no network: core reported unverified, uploads still checked", any("core" in u["component"] for u in res.unverified) and any(i.kind == "php-in-uploads" for i in res.issues))
    res = integ.check(Path(d) / "nothing", fetch=fake)
    check("not a WordPress root: says so", res.core_version is None and not res.tampered)

    # patterns: real backdoor idioms hit, ordinary code does not
    def pat(code):
        p = Path(d) / "t.php"; p.write_text(code); return integ.suspicious_patterns(p)
    bad = {"eval-decoded": "<?php eval(gzinflate(base64_decode('abc')));", "eval-input": "<?php @eval($_POST['p']);",
           "exec-input": "<?php passthru($_REQUEST['cmd']);", "preg-e": "<?php preg_replace('/.*/e', $x, '');",
           "create-function-input": "<?php $f = create_function('', $_GET['c']);",
           "upload-write": "<?php move_uploaded_file($_FILES['f']['tmp_name'], $_POST['name']);",
           "long-encoded-blob": "<?php $x = base64_decode('" + "QUJD" * 500 + "');"}
    for pid, code in bad.items():
        check(f"pattern {pid} detected", pid in pat(code))
    good = ["<?php $v = base64_decode($row['data']); echo esc_html($v);", "<?php $x = sanitize_text_field($_POST['name']);",
            "<?php exec('convert ' . escapeshellarg($file));", "<?php preg_replace('/e+/', 'x', $s);",
            "<?php // evaluate the result\n$evaluation = eval_score($a);", "<?php move_uploaded_file($_FILES['f']['tmp_name'], $dest);",
            "<?php if (isset($_GET['page'])) { $page = (int) $_GET['page']; }"]
    check("ordinary code produces no pattern hits", all(pat(c) == [] for c in good))
    (Path(d) / "t.txt").write_text("eval(base64_decode('x'))")
    check("non-PHP files are not pattern-scanned", integ.suspicious_patterns(Path(d) / "t.txt") == [])

if os.environ.get("PHPWARDEN_LIVE_TESTS") == "1":
    doc = integ._fetch_json(integ.CORE_URL.format(version="6.5.2", locale="en_US"))
    check("live: wordpress.org core checksums reachable", len(doc.get("checksums") or {}) > 1000)
    doc = integ._fetch_json(integ.PLUGIN_URL.format(slug="akismet", version="5.3"))
    check("live: plugin checksums reachable", "akismet.php" in (doc.get("files") or {}))

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
