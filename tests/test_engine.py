#!/usr/bin/env python3
"""Validate the exposure engine's version/sapi/os logic against known CVE facts."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phpwarden.engine import Environment, assess, assess_one, summarize  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402

FEED = Feed.bundled()

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond

def verdict(ver, cve_id, **env):
    e = Environment.from_version_string(ver, **env)
    c = FEED.by_id(cve_id)
    return assess_one(c, e).verdict

# --- php2shell version boundaries -------------------------------------------
check("8.3.35 EXPOSED to php2shell 109618", verdict("8.3.35", "CVE-2026-109618") == "EXPOSED")
check("8.3.36 CLEARED of php2shell 109618", verdict("8.3.36", "CVE-2026-109618") == "CLEARED")
check("8.2.35 CLEARED of php2shell 109619", verdict("8.2.35", "CVE-2026-109619") == "CLEARED")

# --- CVE-2024-4577 is Windows + CGI only, code-page conditional -------------
check("8.3.7 CGI/Windows POSSIBLY exposed to 4577 (code page unconfirmed)",
      verdict("8.3.7", "CVE-2024-4577", sapi="cgi", os="windows") == "POSSIBLY_EXPOSED")
check("8.3.7 CGI/Windows with code page confirmed -> EXPOSED",
      assess_one(FEED.by_id("CVE-2024-4577"),
                 Environment.from_version_string("8.3.7", sapi="cgi", os="windows",
                     config_true={"windows_cgi_eastasian_codepage"})).verdict == "EXPOSED")
check("8.3.7 FPM/Linux CLEARED of 4577 (wrong SAPI/OS)",
      verdict("8.3.7", "CVE-2024-4577", sapi="fpm", os="linux") == "CLEARED")
check("8.3.7 unknown SAPI/OS only POSSIBLY exposed to 4577",
      verdict("8.3.7", "CVE-2024-4577") == "POSSIBLY_EXPOSED")
check("8.3.8 CLEARED of 4577 (patched)",
      verdict("8.3.8", "CVE-2024-4577", sapi="cgi", os="windows") == "CLEARED")

# --- CVE-2019-11043 is FPM, config-gated ------------------------------------
check("7.2.20 FPM EXPOSED-ish to 11043 (POSSIBLY, config unconfirmed)",
      verdict("7.2.20", "CVE-2019-11043", sapi="fpm") == "POSSIBLY_EXPOSED")
check("7.2.20 FPM with config confirmed -> EXPOSED",
      assess_one(FEED.by_id("CVE-2019-11043"),
                 Environment.from_version_string("7.2.20", sapi="fpm",
                     config_true={"nginx_fastcgi_split_path_info_anchored", "no_file_existence_guard"})).verdict == "EXPOSED")
check("7.2.24 CLEARED of 11043", verdict("7.2.24", "CVE-2019-11043", sapi="fpm") == "CLEARED")

# --- EOL branch handling ----------------------------------------------------
check("7.2.x EOL-affected by php2shell (no upstream fix for 7.x)",
      verdict("7.2.24", "CVE-2026-109618") in ("POSSIBLY_EXPOSED", "EXPOSED"))
check("8.3.x NOT applicable to phar 3824 (branch newer than listed 8.2 max)",
      verdict("8.3.0", "CVE-2023-3824") == "CLEARED")
check("8.2.7 POSSIBLY exposed to phar 3824 (untrusted-phar conditional)",
      verdict("8.2.7", "CVE-2023-3824") == "POSSIBLY_EXPOSED")

# --- whole-feed assessment of a realistic host ------------------------------
env = Environment.from_version_string("8.3.10", sapi="fpm", os="linux")
findings = assess(env, FEED)
s = summarize(findings)
print("   8.3.10 fpm/linux ->", s)
# 8.3.10: php2shell (fixed 8.3.36) exposed; 2024-11236 (fixed 8.3.14) exposed;
#         2024-8926/8927 (fixed 8.3.12) exposed; 4577 cleared (linux); phar n/a (newer branch)
exposed_ids = {f.cve.id for f in findings if f.verdict == "EXPOSED"}
possible_ids = {f.cve.id for f in findings if f.verdict == "POSSIBLY_EXPOSED"}
check("8.3.10 exposed to php2shell pair",
      {"CVE-2026-109618", "CVE-2026-109619"} <= exposed_ids)
check("8.3.10 exposed to CVE-2024-8927 (fpm, fixed 8.3.12)", "CVE-2024-8927" in exposed_ids)
check("8.3.10 possibly exposed to CVE-2024-11236 (quoting conditional)", "CVE-2024-11236" in possible_ids)
check("8.3.10 cleared of 4577 (linux fpm, not cgi/windows)",
      "CVE-2024-4577" not in exposed_ids and "CVE-2024-4577" not in possible_ids)
check("worst severity is critical", s["worst_severity"] == "critical")

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
