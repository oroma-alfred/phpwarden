"""Detect the local PHP environment: version, SAPI, OS, architecture.

Everything is best-effort and honest: anything we cannot determine is left as
None, which the engine treats as "cannot rule out" rather than "safe".
"""
from __future__ import annotations

import platform
import shutil
import struct
import subprocess

from phpwarden import version as V
from phpwarden.engine import Environment


def _run(cmd):
    try:
        exe = shutil.which(cmd[0]) or cmd[0]
        out = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True,
                             timeout=10, check=False)
        return (out.stdout or out.stderr)
    except (OSError, subprocess.SubprocessError):
        return ""


def detect_os():
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "linux":
        return "linux"
    if s == "darwin":
        return "darwin"
    return None


def detect_arch():
    return "64" if struct.calcsize("P") * 8 == 64 else "32"


def detect(php_binary: str = "php", prefer_fpm: bool = True) -> Environment:
    """Build an Environment from the local machine.

    Tries php-fpm first (so SAPI is known to be fpm) unless told otherwise,
    then falls back to the php CLI for the version.
    """
    version = None
    sapi = None

    def _version_line(out: str):
        # `php -v` may print startup warnings (a missing extension) BEFORE the
        # "PHP 8.x.y (cli) ..." line; take the first line that is a PHP banner.
        for ln in (out or "").splitlines():
            if ln.startswith("PHP ") and V.parse(ln):
                return V.parse(ln)
        return V.parse(out) if out else None

    # An explicit --php means "assess THIS binary": never silently substitute a
    # php-fpm found on PATH for it.
    explicit = php_binary != "php"
    if prefer_fpm and not explicit:
        fpm_out = _run(["php-fpm", "-v"])
        if fpm_out and _version_line(fpm_out):
            version = _version_line(fpm_out)
            sapi = "fpm"

    if version is None:
        out = _run([php_binary, "-v"])
        version = _version_line(out)
        # ask the running SAPI if we can (last line: warnings may precede it)
        sapi_out = _run([php_binary, "-r", "echo PHP_SAPI;"]).strip()
        last = sapi_out.splitlines()[-1].strip() if sapi_out else ""
        if last:
            if "fpm" in last:
                sapi = "fpm"
            elif "cgi" in last:
                sapi = "cgi"
            elif last == "cli":
                sapi = sapi or "cli"

    return Environment(version=version, sapi=sapi, os=detect_os(), arch=detect_arch())
