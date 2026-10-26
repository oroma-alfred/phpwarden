#!/usr/bin/env python3
"""Reachability noise-cut + forensic access-log parsing."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from phpwarden import deps  # noqa: E402
from phpwarden import detect  # noqa: E402

ok = True


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS " if cond else "FAIL ") + name)


# --- reachability ---------------------------------------------------------- #
with tempfile.TemporaryDirectory() as d:
    proj = Path(d)
    lock = {
        "packages": [
            {"name": "monolog/monolog", "version": "1.0.0",
             "autoload": {"psr-4": {"Monolog\\": "src/"}}},
            {"name": "vendor/unused", "version": "2.0.0",
             "autoload": {"psr-4": {"Vendor\\Unused\\": "src/"}}},
            {"name": "legacy/nons", "version": "1.0.0"},   # no autoload namespace
        ],
        "packages-dev": [
            {"name": "phpunit/phpunit", "version": "5.6.2",
             "autoload": {"psr-4": {"PHPUnit\\": "src/"}}},
        ],
    }
    (proj / "composer.lock").write_text(json.dumps(lock))
    (proj / "app.php").write_text("<?php\nuse Monolog\\Logger;\n$l = new Logger('x');\n")
    # vendor/ must be ignored even though it references everything
    (proj / "vendor").mkdir()
    (proj / "vendor" / "big.php").write_text("<?php\nuse Vendor\\Unused\\Thing; use PHPUnit\\X;\n")

    r = deps.analyze_reachability(str(proj / "composer.lock"), str(proj))
    check("referenced package -> used", r["monolog/monolog"] == "used")
    check("unreferenced runtime package -> unreferenced", r["vendor/unused"] == "unreferenced")
    check("dev package not in code -> dev-only", r["phpunit/phpunit"] == "dev-only")
    check("package without autoload namespace -> unknown", r["legacy/nons"] == "unknown")
    check("vendor/ is excluded from the source scan",
          r["vendor/unused"] != "used" and r["phpunit/phpunit"] != "used")

    # 1a: a project dir that does not exist (or has no PHP) is "unknown" for
    # every package — absence of evidence is not "unreferenced".
    r_missing = deps.analyze_reachability(str(proj / "composer.lock"), str(proj / "does-not-exist"))
    check("missing --project dir -> every package unknown",
          r_missing and all(v == "unknown" for v in r_missing.values()))
    empty = proj / "no-php-here"
    empty.mkdir()
    (empty / "README.md").write_text("Monolog\\Logger is mentioned here but this is not PHP\n")
    r_empty = deps.analyze_reachability(str(proj / "composer.lock"), str(empty))
    check("project dir without PHP sources -> every package unknown",
          r_empty and all(v == "unknown" for v in r_empty.values()))

    # 1b: a namespace that appears only inside comments is NOT a use.
    (proj / "app.php").write_text(
        "<?php\n"
        "// Vendor\\Unused\\Thing is only mentioned here\n"
        "# PHPUnit\\Framework\\TestCase as well\n"
        "/* Vendor\\Unused\\Other */\n"
        "/**\n * @see Vendor\\Unused\\Doc\n */\n"
        "use Monolog\\Logger;\n$l = new Logger('x');\n"
        "$s = 'literal // text that looks like a comment stays a string';\n")
    r2 = deps.analyze_reachability(str(proj / "composer.lock"), str(proj))
    check("namespace only in // # /* */ and docblock comments -> NOT used",
          r2["vendor/unused"] == "unreferenced" and r2["phpunit/phpunit"] == "dev-only")
    check("real `use` statement next to comments still counts", r2["monolog/monolog"] == "used")
    stripped = deps.strip_php_comments("<?php $a = 'x // y'; // gone\n#[Attr] $b = 1; # gone\n/* gone */ $c;")
    check("comment stripper keeps string contents and #[attributes]",
          "'x // y'" in stripped and "#[Attr]" in stripped
          and "gone" not in stripped and "$c" in stripped)

# --- 1c: reach influences the ranking ------------------------------------- #
from phpwarden.vulndb import ComposerAdvisory  # noqa: E402


def _adv(pkg, cve, kev=False, epss=0.0, cvss=5.0):
    return deps.DepFinding(pkg, "1.0.0", ComposerAdvisory(
        package=pkg, cve=cve, title=cve, cvss=cvss, severity="high", affected="<2",
        fixed=["2.0.0"], known_exploited=kev, references=[], epss=epss), ["2.0.0"])


findings = [
    _adv("a/dev-high-epss", "CVE-A", epss=0.9, cvss=9.8),
    _adv("b/unref-high-epss", "CVE-B", epss=0.8, cvss=9.8),
    _adv("c/unknown-mid", "CVE-C", epss=0.5),
    _adv("d/used-low-epss", "CVE-D", epss=0.01, cvss=4.0),
    _adv("e/kev-unref", "CVE-E", kev=True, epss=0.02),
    _adv("f/used-low-epss-high-cvss", "CVE-F", epss=0.01, cvss=9.0),
]
reach = {"a/dev-high-epss": "dev-only", "b/unref-high-epss": "unreferenced",
         "d/used-low-epss": "used", "e/kev-unref": "unreferenced",
         "f/used-low-epss-high-cvss": "used"}   # c/ is absent -> unknown
order = [f.package for f in deps.rank_findings(findings, reach)]
check("KEV ranks first even when unreferenced", order[0] == "e/kev-unref")
check("used packages outrank unknown, unreferenced and dev-only regardless of EPSS",
      order[1:3] == ["f/used-low-epss-high-cvss", "d/used-low-epss"])
check("within equal reach + EPSS, higher CVSS first", order.index("f/used-low-epss-high-cvss") < order.index("d/used-low-epss"))
check("unknown outranks unreferenced", order.index("c/unknown-mid") < order.index("b/unref-high-epss"))
check("unreferenced outranks dev-only", order.index("b/unref-high-epss") < order.index("a/dev-high-epss"))
check("rank_findings with no reach map treats everything as unknown (EPSS order)",
      [f.package for f in deps.rank_findings(findings)][:2] == ["e/kev-unref", "a/dev-high-epss"])

# --- forensic access-log parsing ------------------------------------------- #
line = ('45.148.10.12 - - [24/Oct/2026:08:43:12 +0000] '
        '"POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 200 12 '
        '"-" "python-requests/2.31"')
p = detect.parse_access_line(line)
check("parses client IP", p.get("ip") == "45.148.10.12")
check("parses request", p.get("req", "").startswith("POST /vendor/phpunit"))
check("parses status", p.get("status") == "200")
check("parses user-agent", p.get("ua") == "python-requests/2.31")
check("parses timestamp to epoch", isinstance(p.get("log_ts"), int) and p["log_ts"] > 0)

# scan_line carries the structured fields onto the Hit
from phpwarden.vulndb import Feed  # noqa: E402
sc = detect.SignatureScanner(Feed.bundled())
hits = sc.scan_line('1.2.3.4 - - [24/Oct/2026:01:02:03 +0000] "GET /x%0a HTTP/1.1" 404 0 "-" "curl/8"',
                    "access", 7)
check("scan_line attaches IP/time to the hit",
      any(h.ip == "1.2.3.4" and h.log_ts and h.line_no == 7 for h in hits) if hits else False)

print("\nRESULT: " + ("ALL PASS" if ok else "FAILURES"))
sys.exit(0 if ok else 1)
