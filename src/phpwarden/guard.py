#!/usr/bin/env python3
"""php2shell-guard — autonomous-defense daemon.

Implements the Claude<->Grok build contract in DESIGN.md.

Build order honored: status + self-probe + census + killswitch, THEN the
actuation half (pid-join parser, worker-kill / pool-recycle, breaker counters).

Safety model (do not weaken without re-reading DESIGN.md invariants):
  * Boot mode is DRYRUN. Reaching ENFORCE requires an operator ack file AND the
    P1-P7 promotion guards AND the --allow-enforce flag. Absent any of these the
    destructive os.kill / recycle paths are unreachable.
  * "daemon up" != "protected": detection_claim is LIVE only when pid-join is
    honestly armed; missing plumbing => REFUSED.
  * Killswitch ACTIVE forces DRYRUN (fail-open on kills) but census, canary,
    alerting, would_have recording and the deploy gate keep running.
  * Breakers cap actuation so the daemon cannot self-DoS the fleet.
  * v1 never edits FPM config; it only reads and recommends.

Zero dependencies (Python 3.8+, stdlib only). Self-contained version census.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import deque
from pathlib import Path

# --------------------------------------------------------------------------- #
# Version census (self-contained): parse a PHP version and classify it against
# the php2shell-class fix releases. Status one of PATCHED / VULNERABLE / EOL /
# UNKNOWN — the guard only actuates on a non-PATCHED engine (invariant 7).
# --------------------------------------------------------------------------- #
_PRERELEASE = re.compile(r"(?i)(?:-|~)?(alpha|beta|rc|dev|snapshot)")
# First fixed release per branch for the php2shell worker-poisoning CVEs.
PATCHED_MIN = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
NEWEST_KNOWN_BRANCH = (8, 5)
CVES = "CVE-2026-109618, CVE-2026-109619"


def parse_version(text: str):
    """Extract (major, minor, patch, is_prerelease) from a PHP version string,
    or None. A prerelease sorts below the final release of the same X.Y.Z."""
    if not text:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        return None
    major, minor, patch = (int(m.group(i)) for i in (1, 2, 3))
    return major, minor, patch, bool(_PRERELEASE.search(text[m.end():]))


def classify(version_tuple):
    """Return (status, message). status: PATCHED / VULNERABLE / EOL / UNKNOWN."""
    if version_tuple is None:
        return "UNKNOWN", "Could not parse a PHP version (X.Y.Z)."
    major, minor, patch, is_pre = version_tuple
    branch, ver = (major, minor), (major, minor, patch)
    label = f"{major}.{minor}.{patch}" + (" (prerelease)" if is_pre else "")
    if branch > NEWEST_KNOWN_BRANCH:
        if is_pre:
            return "UNKNOWN", f"{label}: prerelease on a branch newer than known; confirm it includes {CVES}."
        return "PATCHED", f"{label}: branch newer than the vulnerable set; fixes included upstream."
    if branch in PATCHED_MIN:
        min_safe = PATCHED_MIN[branch]
        safe = ".".join(map(str, min_safe))
        if ver > min_safe or (ver == min_safe and not is_pre):
            return "PATCHED", f"{label}: at or above the fixed release {safe} for {major}.{minor}."
        return "VULNERABLE", f"{label}: below the fixed release {safe} for {major}.{minor}. Update now. ({CVES})"
    return "EOL", f"{label}: end-of-life branch, no fix available. ({CVES})"


UTC = _dt.timezone.utc
STATE_DIR_DEFAULT = "data/php2shell-guard"


def now_iso() -> str:
    return _dt.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch() -> float:
    return time.time()


# --------------------------------------------------------------------------- #
# Killswitch
# --------------------------------------------------------------------------- #
KILLSWITCH_SEARCH = [
    "/etc/php2shell-guard/killswitch.json",
    "data/php2shell-guard/killswitch.json",
]


def load_killswitch():
    paths = list(KILLSWITCH_SEARCH)
    env = os.environ.get("PHP2SHELL_KILLSWITCH_PATH")
    if env:
        paths.append(env)
    for p in paths:
        fp = Path(p)
        if not fp.exists():
            continue
        try:
            data = json.loads(fp.read_text())
        except (OSError, ValueError):
            return "ACTIVE", {"reason": "killswitch_corrupt_failsafe", "path": p}
        if data.get("tripped"):
            return "ACTIVE", {"reason": data.get("reason", ""), "path": p,
                              "scopes": data.get("scopes", {})}
        if data.get("hold"):
            return "HOLD", {"reason": data.get("reason", ""), "path": p}
        return "OFF", {"path": p}
    return "OFF", {"path": None}


# --------------------------------------------------------------------------- #
# Version census (deterministic)
# --------------------------------------------------------------------------- #
def census(pool: dict):
    ver_text = pool.get("php_version")
    if not ver_text:
        binary = pool.get("php_binary", "php-fpm")
        try:
            out = subprocess.run([binary, "-v"], capture_output=True, text=True,
                                 timeout=10, check=False)
            lines = (out.stdout or out.stderr).splitlines()
            ver_text = lines[0] if lines else None
        except (OSError, subprocess.SubprocessError):
            ver_text = None
    parsed = parse_version(ver_text) if ver_text else None
    status, _msg = classify(parsed)
    ver = ".".join(map(str, parsed[:3])) if parsed else None
    return status, ver


# --------------------------------------------------------------------------- #
# Log cursors: read only new bytes each tick, survive restarts
# --------------------------------------------------------------------------- #
class LogCursor:
    """Tails a file by remembering a byte offset. Handles truncation/rotation."""

    def __init__(self, path: str, offset: int = 0, inode: int = 0):
        self.path = path
        self.offset = offset
        self.inode = inode

    def to_dict(self):
        return {"path": self.path, "offset": self.offset, "inode": self.inode}

    def read_new(self):
        fp = Path(self.path)
        if not fp.exists() or not os.access(self.path, os.R_OK):
            return []
        st = fp.stat()
        # rotation (new inode) or truncation (shrunk) -> restart from 0
        if st.st_ino != self.inode or st.st_size < self.offset:
            self.offset = 0
            self.inode = st.st_ino
        try:
            with fp.open("r", errors="replace") as fh:
                fh.seek(self.offset)
                data = fh.read()
                self.offset = fh.tell()
        except OSError:
            return []
        return data.splitlines()


# --------------------------------------------------------------------------- #
# pid-join parser + correlator
# --------------------------------------------------------------------------- #
# Access-log parsing. A pool may override with "access_log_regex" (named groups:
# pid, status). Otherwise we find the worker pid and the response status with two
# independent searches, which is robust to field order and log format. Multipart
# is sniffed from a logged Content-Type.
_ACCESS_PID_RE = re.compile(r'(?:upstream_pid|\bpid)[=:\s]+(\d+)|\bchild\s+(\d+)', re.I)
_ACCESS_STATUS_RE = re.compile(r'"\s*[A-Z]+[^"]*"\s+(\d{3})')
# FPM error/catch_workers_output: child pid + OOM/fatal markers.
_FATAL_PID_RE = re.compile(r"child\s+(\d+)", re.I)
_OOM_RE = re.compile(
    r"allowed memory size|memory_limit|exhausted|exited on signal\s*(?:9|11)|SIGKILL|SIGSEGV|"
    r"out of memory|oom",
    re.I,
)
_MULTIPART_RE = re.compile(r"multipart/form-data", re.I)


def parse_access_line(line: str, custom_re: re.Pattern = None):
    """Return dict(pid, status, multipart) or None."""
    if custom_re is not None:
        m = custom_re.search(line)
        if not m:
            return None
        gd = m.groupdict()
        pid, status = gd.get("pid"), gd.get("status")
        if status is None:
            return None
        return {
            "pid": int(pid) if pid and str(pid).isdigit() else None,
            "status": int(status),
            "multipart": bool(_MULTIPART_RE.search(line)),
        }
    sm = _ACCESS_STATUS_RE.search(line)
    if not sm:
        return None
    pm = _ACCESS_PID_RE.search(line)
    pid = (pm.group(1) or pm.group(2)) if pm else None
    return {
        "pid": int(pid) if pid else None,
        "status": int(sm.group(1)),
        "multipart": bool(_MULTIPART_RE.search(line)),
    }


def parse_fatal_line(line: str):
    """Return (pid, kind) when the line is an OOM/fatal with a worker pid."""
    if not _OOM_RE.search(line):
        return None
    m = _FATAL_PID_RE.search(line)
    if not m:
        return None
    return int(m.group(1)), "oom_or_fatal"


class JoinCorrelator:
    """Core detector: fatal/OOM on worker P, then anomalous reuse of P.

    Emits a suspicion event when, within `window_s` of a fatal on pid P, that
    same pid P serves requests showing the aftermath (500s, or a multipart tie),
    i.e. the worker did not die clean and is being reused.
    """

    def __init__(self, window_s: int = 120, min_anomalies: int = 2):
        self.window_s = window_s
        self.min_anomalies = min_anomalies
        self.last_fatal = {}        # pid -> epoch of last fatal
        self.anomaly_count = {}     # pid -> count since fatal

    def feed_fatal(self, pid: int, ts: float):
        self.last_fatal[pid] = ts
        self.anomaly_count[pid] = 0

    def feed_access(self, rec: dict, ts: float):
        pid = rec.get("pid")
        if pid is None or pid not in self.last_fatal:
            return None
        if ts - self.last_fatal[pid] > self.window_s:
            # stale; forget it
            self.last_fatal.pop(pid, None)
            self.anomaly_count.pop(pid, None)
            return None
        anomalous = rec["status"] >= 500 or rec["multipart"]
        if anomalous:
            self.anomaly_count[pid] = self.anomaly_count.get(pid, 0) + 1
            if self.anomaly_count[pid] >= self.min_anomalies:
                evidence = {
                    "pid": pid,
                    "fatal_age_s": round(ts - self.last_fatal[pid], 1),
                    "anomalies": self.anomaly_count[pid],
                }
                # one event per fatal episode
                self.last_fatal.pop(pid, None)
                self.anomaly_count.pop(pid, None)
                return {"pid": pid, "reason": "oom_then_reuse", "evidence": evidence}
        return None


def run_pid_join(pool: dict, cursors: dict, correlator: JoinCorrelator):
    """Read new access + fatal lines, return list of suspicion events."""
    events = []
    custom = pool.get("access_log_regex")
    custom_re = re.compile(custom) if custom else None

    fatal_path = pool.get("fatal_log") or pool.get("error_log")
    if fatal_path:
        fc = cursors.setdefault("fatal:" + fatal_path, LogCursor(fatal_path))
        for line in fc.read_new():
            parsed = parse_fatal_line(line)
            if parsed:
                correlator.feed_fatal(parsed[0], _epoch())

    acc_path = pool.get("access_log")
    if acc_path:
        ac = cursors.setdefault("access:" + acc_path, LogCursor(acc_path))
        for line in ac.read_new():
            rec = parse_access_line(line, custom_re)
            if rec:
                ev = correlator.feed_access(rec, _epoch())
                if ev:
                    ev["pool"] = pool.get("pool")
                    events.append(ev)
    return events


# --------------------------------------------------------------------------- #
# Circuit breakers
# --------------------------------------------------------------------------- #
class Breakers:
    """Rolling-window caps so actuation cannot self-DoS the fleet."""

    WINDOW = 600                 # 10 minutes
    RECYCLE_PER_POOL = 1
    RECYCLE_PER_HOST = 3
    KILL_PER_POOL = 2
    KILL_FRACTION_PER_TICK = 0.25
    COOLDOWN_AFTER_RECYCLE = 120

    def __init__(self, state: dict):
        self.actions = deque(state.get("actions", []))      # list of {ts,scope,type}
        self.frozen_until = state.get("frozen_until")
        self.frozen_reason = state.get("frozen_reason")

    def to_dict(self):
        self._evict()
        return {
            "actions": list(self.actions),
            "frozen_until": self.frozen_until,
            "frozen_reason": self.frozen_reason,
        }

    def _evict(self):
        cut = _epoch() - self.WINDOW
        while self.actions and self.actions[0]["ts"] < cut:
            self.actions.popleft()

    def _count(self, type_=None, scope=None):
        self._evict()
        return sum(1 for a in self.actions
                   if (type_ is None or a["type"] == type_)
                   and (scope is None or a["scope"] == scope))

    def status(self):
        if self.frozen_until and _epoch() < self.frozen_until:
            return f"FROZEN:{self.frozen_reason}"
        return "OK"

    def freeze(self, reason: str, seconds: int = WINDOW):
        self.frozen_until = _epoch() + seconds
        self.frozen_reason = reason

    def allow_recycle(self, pool: str, deploy_guarded: bool):
        if self.status() != "OK":
            return False, self.status()
        if deploy_guarded:
            return False, "deploy_or_load_guard"
        # cooldown: no actuation on a pool within 120s of its last recycle
        last = [a for a in self.actions
                if a["type"] == "POOL_RECYCLE" and a["scope"] == f"pool:{pool}"]
        if last and _epoch() - last[-1]["ts"] < self.COOLDOWN_AFTER_RECYCLE:
            return False, "cooldown"
        if self._count("POOL_RECYCLE", f"pool:{pool}") >= self.RECYCLE_PER_POOL:
            return False, "pool_recycle_cap"
        if self._count("POOL_RECYCLE", "host") >= self.RECYCLE_PER_HOST:
            self.freeze("fleet_recycle_cap")
            return False, "fleet_frozen"
        return True, "ok"

    def allow_kill(self, pool: str, workers: int, killed_this_tick: int, deploy_guarded: bool):
        if self.status() != "OK":
            return False, self.status()
        if deploy_guarded:
            return False, "deploy_or_load_guard"
        if self._count("WORKER_KILL", f"pool:{pool}") >= self.KILL_PER_POOL:
            return False, "pool_kill_cap"
        max_this_tick = max(1, int(workers * self.KILL_FRACTION_PER_TICK))
        if killed_this_tick >= max_this_tick:
            return False, "tick_fraction_cap"
        return True, "ok"

    def record(self, type_: str, pool: str):
        ts = _epoch()
        self.actions.append({"ts": ts, "scope": f"pool:{pool}", "type": type_})
        self.actions.append({"ts": ts, "scope": "host", "type": type_})


def deploy_guard_active(pool: dict) -> bool:
    """Suppress actuation during deploys / load spikes (contract: deploy/load guard)."""
    lock = pool.get("deploy_lock", "data/php2shell-guard/deploy.lock")
    fresh = 300
    if lock and Path(lock).exists():
        try:
            if _epoch() - Path(lock).stat().st_mtime < fresh:
                return True
        except OSError:
            pass
    # conf mtime burst: a just-reloaded pool is churning for benign reasons
    conf = pool.get("fpm_conf")
    if conf and Path(conf).exists():
        try:
            if _epoch() - Path(conf).stat().st_mtime < fresh:
                return True
        except OSError:
            pass
    return False


# --------------------------------------------------------------------------- #
# Actuators (reachable only in ENFORCE with all guards satisfied)
# --------------------------------------------------------------------------- #
def actuate_worker_kill(pid: int) -> dict:
    """Signal a single poisoned worker; the FPM master respawns it clean."""
    try:
        os.kill(pid, signal.SIGTERM)
        return {"ok": True}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def actuate_pool_recycle(pool: dict) -> dict:
    """Graceful pool recycle. Prefers a configured command, else SIGUSR2 master."""
    cmd = pool.get("recycle_command")
    if cmd:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return {"ok": r.returncode == 0, "rc": r.returncode, "err": r.stderr[:200]}
        except (OSError, subprocess.SubprocessError) as e:
            return {"ok": False, "error": str(e)}
    master = pool.get("master_pid")
    if master:
        try:
            os.kill(int(master), signal.SIGUSR2)   # FPM graceful reload
            return {"ok": True, "method": "SIGUSR2"}
        except (OSError, ValueError) as e:
            return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "no_recycle_command_or_master_pid"}


# --------------------------------------------------------------------------- #
# Promotion guards P1-P7 (never auto-promote; human + ack + flag required)
# --------------------------------------------------------------------------- #
def promotion_guards(pool_status: dict, killswitch_state: str, ack: dict):
    """Return (ok, failed[]). P6 (72h clean or ack) is operator-driven."""
    failed = []
    if pool_status["census"] in ("EOL", "UNKNOWN"):                 # P1
        failed.append("P1_census")
    if not pool_status["max_requests_ok"]:                          # P2
        failed.append("P2_max_requests")
    if pool_status["pid_join"] != "ARMED":                          # P3
        failed.append("P3_pid_join")
    if pool_status["canary"] not in ("OK",):                        # P4
        failed.append("P4_canary_baseline")
    if killswitch_state != "OFF":                                   # P5
        failed.append("P5_killswitch")
    if not ack.get(pool_status["pool"]):                            # P6
        failed.append("P6_burnin_or_ack")
    if not pool_status.get("audit_ok", True):                       # P7
        failed.append("P7_audit")
    return (not failed), failed


# --------------------------------------------------------------------------- #
# Self-probe
# --------------------------------------------------------------------------- #
_PID_FIELD = re.compile(r"(?:\$?upstream_pid|%p|\bpid[=:]\s*\d+|child\s+\d+)", re.I)


def probe_max_requests(pool: dict):
    conf = pool.get("fpm_conf")
    if not conf or not Path(conf).exists():
        return None, False
    try:
        text = Path(conf).read_text(errors="replace")
    except OSError:
        return None, False
    m = re.search(r"^\s*pm\.max_requests\s*=\s*(\d+)", text, re.M)
    if not m:
        return None, False
    val = int(m.group(1))
    return val, (0 < val <= 500)


def probe_pid_join(pool: dict):
    access_log = pool.get("access_log")
    if not access_log:
        return False, "no_access_log_configured"
    fp = Path(access_log)
    if not fp.exists() or not os.access(access_log, os.R_OK):
        return False, "access_log_unreadable"
    try:
        with fp.open(errors="replace") as fh:
            tail = fh.readlines()[-100:]
    except OSError:
        return False, "access_log_unreadable"
    if not any(_PID_FIELD.search(line) for line in tail):
        return False, "no_upstream_pid_field"
    return True, None


def probe_signal_permission(pool: dict):
    pid = pool.get("sample_worker_pid") or pool.get("master_pid")
    if not pid:
        return False, "no_sample_worker_pid"
    try:
        os.kill(int(pid), 0)
        return True, None
    except (OSError, ValueError) as e:
        return False, f"no_signal_permission:{e.__class__.__name__}"


def probe_audit_writable(audit_path: str):
    try:
        Path(audit_path).parent.mkdir(parents=True, exist_ok=True)
        with open(audit_path, "a"):
            pass
        return True, None
    except OSError:
        return False, "audit_log_unwritable"


def probe_canary(pool: dict):
    url = pool.get("canary_url")
    if not url:
        return "DISABLED", {"reason": "no_canary_url"}
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "php2shell-guard-canary"})
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            set_cookie = resp.headers.get("Set-Cookie", "")
    except Exception as e:  # noqa: BLE001
        return "TRIPPED", {"reason": f"canary_request_failed:{e.__class__.__name__}"}
    m = re.search(r"PHPSESSID=([^;]+)", set_cookie)
    if not m:
        return "OK", {"note": "no_phpsessid_in_response", "ts": now_iso()}
    sid = m.group(1)
    if len(sid) > 128 or not re.fullmatch(r"[A-Za-z0-9,\-]{8,96}", sid):
        return "TRIPPED", {"reason": "phpsessid_grammar_violation", "len": len(sid)}
    return "OK", {"ts": now_iso()}


# --------------------------------------------------------------------------- #
# Per-pool evaluation + actuation decision
# --------------------------------------------------------------------------- #
def evaluate_pool(pool, killswitch_state, audit_path, mode, cursors,
                  correlators, breakers, ack, enforce_allowed):
    name = pool.get("pool", "default")
    workers = int(pool.get("workers", 1))
    census_status, php_version = census(pool)
    mr_val, mr_ok = probe_max_requests(pool)

    pid_partial, pid_reason = probe_pid_join(pool)
    sig_ok, sig_reason = (True, None)
    audit_ok, audit_reason = probe_audit_writable(audit_path)
    if pid_partial:
        sig_ok, sig_reason = probe_signal_permission(pool)

    disarm = None
    if killswitch_state != "OFF":
        disarm = f"killswitch_{killswitch_state.lower()}"
    elif not pid_partial:
        disarm = pid_reason
    elif not sig_ok:
        disarm = sig_reason
    elif not audit_ok:
        disarm = audit_reason
    elif not mr_ok:
        disarm = "max_requests_not_ok"
    pid_join = "ARMED" if disarm is None else f"DISARMED:{disarm}"

    canary_state, canary_detail = probe_canary(pool)
    canary_field = canary_state if canary_state in ("TRIPPED", "DISABLED") else "OK"

    if pid_join == "ARMED" and canary_field == "OK":
        claim = "LIVE"
    elif pid_join == "ARMED" and canary_field == "DISABLED":
        claim = "DEGRADED"
    else:
        claim = "REFUSED"

    pstat = {
        "pool": name, "php_version": php_version, "census": census_status,
        "max_requests": mr_val, "max_requests_ok": mr_ok,
        "pid_join": pid_join, "canary": canary_field, "canary_detail": canary_detail,
        "detection_claim": claim, "audit_ok": audit_ok,
    }

    # --- detection: run the pid-join parser over new log lines ----------------
    corr = correlators.setdefault(name, JoinCorrelator())
    events = []
    if pid_partial:  # only meaningful if we can read logs at all
        events = run_pid_join(pool, cursors, corr)

    # canary TRIPPED demotes enforce + is itself an event (no kill from canary)
    deploy_guarded = deploy_guard_active(pool)
    would = compute_base_would_have(pool, census_status, claim, mr_ok)
    killed_this_tick = 0

    # effective mode for this pool: requires the P1-P7 promotion guards to pass,
    # which includes the operator ack (P6). Automation can never self-promote.
    guards_ok, failed_guards = promotion_guards(pstat, killswitch_state, ack)
    pool_enforce = (mode == "ENFORCE" and enforce_allowed and guards_ok
                    and pid_join == "ARMED" and killswitch_state == "OFF"
                    and canary_field != "TRIPPED")
    pstat["promotion_failed"] = failed_guards

    for ev in events:
        decision = decide_and_act(ev, pool, pstat, breakers, workers,
                                  killed_this_tick, deploy_guarded, pool_enforce,
                                  audit_path)
        would.append(decision["ledger"])
        if decision.get("killed"):
            killed_this_tick += 1

    if canary_field == "TRIPPED":
        would.append({"action": "demote_to_dryrun", "detail": "canary tripped",
                      "executed": pool_enforce, "suppressed_by": None})

    pstat.update({
        "enforce_mode": "ENFORCE" if pool_enforce else "DRYRUN",
        "killswitch": killswitch_state,
        "breakers": breakers.status(),
        "last_action": next((w for w in reversed(would) if w.get("executed")), None),
        "would_have_actions": would,
        "events": events,
    })
    return pstat


def compute_base_would_have(pool, census_status, claim, mr_ok):
    out = []
    if census_status in ("VULNERABLE", "EOL", "UNKNOWN"):
        out.append({"action": "alert", "detail": f"census={census_status}; patch + contain",
                    "executed": False, "suppressed_by": None})
    if census_status in ("VULNERABLE", "EOL") and not mr_ok:
        out.append({"action": "recommend_pm_max_requests",
                    "detail": "set pm.max_requests (e.g. 128 exposed); not auto-edited",
                    "executed": False, "suppressed_by": None})
    if claim == "REFUSED":
        out.append({"action": "note", "detail": "no pid-join; behavioral detectors cannot actuate",
                    "executed": False, "suppressed_by": "no_pid_join"})
    return out


def decide_and_act(ev, pool, pstat, breakers, workers, killed_this_tick,
                   deploy_guarded, pool_enforce, audit_path):
    """Choose WORKER_KILL (preferred) or escalate to POOL_RECYCLE, honoring breakers."""
    pid = ev["pid"]
    name = pstat["pool"]
    # PATCHED census => behavioral detectors never kill (invariant 7)
    if pstat["census"] == "PATCHED":
        return {"ledger": {"action": "noop", "detail": "census PATCHED; no kill",
                           "event": ev, "executed": False, "suppressed_by": "census_patched"}}

    allowed, why = breakers.allow_kill(name, workers, killed_this_tick, deploy_guarded)
    if not allowed:
        return {"ledger": {"action": "worker_kill", "pid": pid, "event": ev,
                           "executed": False, "suppressed_by": why}}

    if not pool_enforce:
        return {"ledger": {"action": "worker_kill", "pid": pid, "event": ev,
                           "executed": False, "suppressed_by": "dryrun"}}

    # ENFORCE path (reachable only after promotion)
    result = actuate_worker_kill(pid)
    breakers.record("WORKER_KILL", name)
    append_audit(audit_path, {"ts": now_iso(), "action": "WORKER_KILL",
                              "pool": name, "pid": pid, "event": ev, "result": result})
    return {"killed": result.get("ok", False),
            "ledger": {"action": "worker_kill", "pid": pid, "event": ev,
                       "executed": True, "result": result, "suppressed_by": None}}


def append_audit(audit_path, record):
    try:
        with open(audit_path, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# State persistence (cursors + breakers)
# --------------------------------------------------------------------------- #
def load_state(state_dir):
    fp = Path(state_dir) / "guard_state.json"
    if fp.exists():
        try:
            return json.loads(fp.read_text())
        except (OSError, ValueError):
            return {}
    return {}


def save_state(state_dir, cursors, breakers):
    fp = Path(state_dir) / "guard_state.json"
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(json.dumps({
            "cursors": {k: c.to_dict() for k, c in cursors.items()},
            "breakers": breakers.to_dict(),
        }, indent=2))
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Tick / loop
# --------------------------------------------------------------------------- #
def tick(config, mode, correlators, enforce_allowed):
    state_dir = config.get("state_dir", STATE_DIR_DEFAULT)
    audit_path = config.get("audit_log", str(Path(state_dir) / "actions.jsonl"))
    ks_state, ks_detail = load_killswitch()

    raw = load_state(state_dir)
    cursors = {k: LogCursor(**v) for k, v in raw.get("cursors", {}).items()}
    breakers = Breakers(raw.get("breakers", {}))
    ack = config.get("enforce_ack", {})   # {pool: true} set by operator only

    pools = []
    for p in config.get("pools", []):
        pstat = evaluate_pool(p, ks_state, audit_path, mode, cursors,
                              correlators, breakers, ack, enforce_allowed)
        pools.append(pstat)

    save_state(state_dir, cursors, breakers)
    status = {
        "ts": now_iso(),
        "requested_mode": mode,
        "enforce_allowed": enforce_allowed,
        "killswitch": {"state": ks_state, **ks_detail},
        "breakers": breakers.status(),
        "pools": pools,
    }
    out = config.get("status_file", str(Path(state_dir) / "status.json"))
    try:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(status, indent=2))
    except OSError:
        pass
    return status


def render(status):
    print(f"php2shell-guard  requested={status['requested_mode']} "
          f"enforce_allowed={status['enforce_allowed']} "
          f"killswitch={status['killswitch']['state']} breakers={status['breakers']} {status['ts']}")
    for p in status["pools"]:
        print(f"  pool {p['pool']}: census={p['census']} php={p['php_version']} "
              f"max_requests={p['max_requests']}({'ok' if p['max_requests_ok'] else 'NO'}) "
              f"pid_join={p['pid_join']} canary={p['canary']} "
              f"claim={p['detection_claim']} mode={p['enforce_mode']}")
        for w in p["would_have_actions"]:
            sup = f" [suppressed_by={w['suppressed_by']}]" if w.get("suppressed_by") else ""
            ex = "EXECUTED " if w.get("executed") else "would: "
            print(f"      {ex}{w['action']} — {w.get('detail','')}{sup}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="php2shell autonomous-defense daemon")
    ap.add_argument("--config", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--loop", type=int, metavar="SECONDS")
    ap.add_argument("--mode", choices=["DRYRUN", "ENFORCE"], default="DRYRUN",
                    help="requested mode; ENFORCE also needs --allow-enforce and passing P1-P7")
    ap.add_argument("--allow-enforce", action="store_true",
                    help="operator safety latch; without it ENFORCE is downgraded to DRYRUN")
    args = ap.parse_args(argv)

    try:
        config = json.loads(Path(args.config).read_text())
    except (OSError, ValueError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    mode = args.mode
    enforce_allowed = bool(args.allow_enforce) and mode == "ENFORCE"
    if mode == "ENFORCE" and not args.allow_enforce:
        print("NOTE: --mode ENFORCE ignored without --allow-enforce; staying DRYRUN", file=sys.stderr)
        mode = "DRYRUN"

    correlators = {}   # persists across ticks within one process
    while True:
        status = tick(config, mode, correlators, enforce_allowed)
        print(json.dumps(status, indent=2)) if args.json else render(status)
        if not args.loop:
            return 0
        time.sleep(max(5, args.loop))


if __name__ == "__main__":
    sys.exit(main())
