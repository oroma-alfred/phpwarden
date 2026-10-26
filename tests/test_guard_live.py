#!/usr/bin/env python3
"""Runtime-guard validation.

Two layers:
  1. Detector unit test (always runs): the JoinCorrelator flags a worker that
     took a fatal and keeps serving 500s ("oom_then_reuse").
  2. Live integration test (skips if php-fpm is absent): stands up a REAL
     php-fpm pool, drives REAL traffic over FastCGI, and asserts the guard
       - ENFORCE on a vulnerable host  -> SIGTERMs the worker, master respawns
       - DRYRUN                        -> detects but does NOT kill
       - ENFORCE on a PATCHED host     -> detects but does NOT kill (invariant 7)

No exploit is run: the "poisoned worker" observable (a memory/OOM fatal tagged
to the worker PID, then 500s on that same PID) is reproduced with a benign
script, which is exactly the signal the guard keys on.
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from phpwarden import guard  # noqa: E402

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name); ok = ok and cond


# --------------------------------------------------------------------------- #
# 1. Detector unit test (no php-fpm needed)
# --------------------------------------------------------------------------- #
def test_detector():
    corr = guard.JoinCorrelator(window_s=120, min_anomalies=2)
    now = time.time()
    corr.feed_fatal(4242, now)
    e1 = corr.feed_access({"pid": 4242, "status": 500, "multipart": False}, now)
    e2 = corr.feed_access({"pid": 4242, "status": 500, "multipart": False}, now)
    check("detector: single 500 does not trip", e1 is None)
    check("detector: second 500 after fatal trips oom_then_reuse",
          e2 and e2["reason"] == "oom_then_reuse" and e2["pid"] == 4242)
    # a clean worker (no prior fatal) is never flagged
    corr2 = guard.JoinCorrelator()
    check("detector: 500 without a prior fatal is ignored",
          corr2.feed_access({"pid": 99, "status": 500, "multipart": False}, now) is None)
    # classify sanity
    check("classify: 8.3.0 vulnerable", guard.classify(guard.parse_version("PHP 8.3.0"))[0] == "VULNERABLE")
    check("classify: 8.5.12 patched", guard.classify(guard.parse_version("PHP 8.5.12"))[0] == "PATCHED")


# --------------------------------------------------------------------------- #
# Minimal FastCGI client
# --------------------------------------------------------------------------- #
def fcgi(host, port, script):
    BEGIN, END, PARAMS, STDIN, STDOUT = 1, 3, 4, 5, 6
    def rec(t, c=b""): return struct.pack("!BBHHBB", 1, t, 1, len(c), 0, 0) + c
    def nv(n, v):
        n, v = n.encode(), v.encode()
        el = lambda x: struct.pack("!B", x) if x < 128 else struct.pack("!I", x | 0x80000000)
        return el(len(n)) + el(len(v)) + n + v
    params = {"SCRIPT_FILENAME": script, "SCRIPT_NAME": "/" + Path(script).name,
              "REQUEST_METHOD": "GET", "REQUEST_URI": "/" + Path(script).name,
              "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
              "QUERY_STRING": "", "REMOTE_ADDR": "127.0.0.1", "SERVER_SOFTWARE": "t"}
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(rec(BEGIN, struct.pack("!HB5x", 1, 0)))
    s.sendall(rec(PARAMS, b"".join(nv(k, v) for k, v in params.items())))
    s.sendall(rec(PARAMS)); s.sendall(rec(STDIN))
    while True:
        h = s.recv(8)
        if len(h) < 8:
            break
        _, t, _, clen, plen, _ = struct.unpack("!BBHHBB", h)
        body = b""
        while len(body) < clen + plen:
            ch = s.recv(clen + plen - len(body))
            if not ch:
                break
            body += ch
        if t == END:
            break
    s.close()


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _worker_pid(conf):
    out = subprocess.run(["pgrep", "-f", f"pool web-public"], capture_output=True, text=True)
    pids = [int(x) for x in out.stdout.split()]
    return pids[0] if pids else None


def test_live():
    fpm = shutil.which("php-fpm") or next(
        (p for p in ["/opt/homebrew/opt/php/sbin/php-fpm", "/usr/sbin/php-fpm",
                     "/usr/local/sbin/php-fpm"] if Path(p).exists()), None)
    if not fpm:
        print("SKIP live integration: php-fpm not found (detector unit test still ran)")
        return

    tmp = Path(tempfile.mkdtemp(prefix="pwguard-"))
    www, state = tmp / "www", tmp / "state"
    www.mkdir(); state.mkdir()
    port, cport = _free_port(), _free_port()
    (www / "ok.php").write_text("<?php header('Content-Type: text/plain'); echo 'ok '.getmypid();")
    (www / "boom.php").write_text(
        "<?php $p=getmypid();"
        "error_log(\"[pool web-public] child $p said into stderr: \\\"PHP message: PHP Fatal error: "
        "Allowed memory size of 8388608 bytes exhausted (tried to allocate 52428800 bytes)\\\"\");"
        "http_response_code(500); echo 'boom';")
    conf = tmp / "fpm.conf"
    conf.write_text(f"""[global]
error_log = {tmp}/fpm-error.log
daemonize = no
pid = {state}/fpm.pid
[web-public]
listen = 127.0.0.1:{port}
pm = static
pm.max_children = 1
pm.max_requests = 200
access.log = {tmp}/fpm-access.log
access.format = "\\"%m %r\\" %s pid:%p %{{mili}}d ms"
catch_workers_output = yes
php_admin_flag[log_errors] = on
php_admin_value[error_log] = {tmp}/fpm-error.log
""")
    # canary stub: plain 200 so the guard's P4 canary probe is OK
    canary = subprocess.Popen([sys.executable, "-m", "http.server", str(cport), "--bind", "127.0.0.1"],
                              cwd=str(tmp), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fpm_proc = subprocess.Popen([fpm, "-F", "-y", str(conf)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # wait for the worker
        w0 = None
        for _ in range(50):
            time.sleep(0.1)
            w0 = _worker_pid(conf)
            if w0:
                break
        check("live: fpm worker started", w0 is not None)
        if not w0:
            return
        # backdate conf so deploy-guard doesn't suppress actuation
        old = time.time() - 86400
        os.utime(conf, (old, old))

        def cfg(php_version):
            return {"state_dir": str(state), "status_file": str(state / "status.json"),
                    "audit_log": str(state / "actions.jsonl"), "enforce_ack": {"web-public": True},
                    "pools": [{"pool": "web-public", "php_version": php_version, "workers": 1,
                               "access_log": str(tmp / "fpm-access.log"),
                               "error_log": str(tmp / "fpm-error.log"),
                               "fatal_log": str(tmp / "fpm-error.log"), "fpm_conf": str(conf),
                               "canary_url": f"http://127.0.0.1:{cport}/", "master_pid": fpm_proc.pid,
                               "sample_worker_pid": fpm_proc.pid}]}

        def drive_poison():
            for _ in range(2):
                fcgi("127.0.0.1", port, str(www / "ok.php"))
            for _ in range(3):
                fcgi("127.0.0.1", port, str(www / "boom.php"))

        def kills(status):
            p = status["pools"][0]
            return p, [w for w in p["would_have_actions"]
                       if w.get("action") == "worker_kill" and w.get("executed")]

        corr = {}
        # --- ENFORCE on a vulnerable host: must kill + respawn ---
        drive_poison()
        st = guard.tick(cfg("PHP 8.3.0 (fpm-fcgi)"), "ENFORCE", corr, True)
        p, executed = kills(st)
        check("live/enforce: census VULNERABLE", p["census"] == "VULNERABLE")
        check("live/enforce: promotion guards all pass", p["promotion_failed"] == [])
        check("live/enforce: detected oom_then_reuse", any(e["reason"] == "oom_then_reuse" for e in p["events"]))
        check("live/enforce: worker_kill EXECUTED", len(executed) == 1)
        time.sleep(0.5)
        w1 = _worker_pid(conf)
        check("live/enforce: worker respawned (pid changed)", w1 is not None and w1 != w0)

        # --- DRYRUN: detect, do not kill ---
        drive_poison()
        st = guard.tick(cfg("PHP 8.3.0 (fpm-fcgi)"), "DRYRUN", corr, False)
        p, executed = kills(st)
        check("live/dryrun: effective mode DRYRUN", p["enforce_mode"] == "DRYRUN")
        check("live/dryrun: detected but no kill executed", len(executed) == 0)
        time.sleep(0.3)
        check("live/dryrun: worker unchanged", _worker_pid(conf) == w1)

        # --- ENFORCE but PATCHED census: detect, do not kill (invariant 7) ---
        drive_poison()
        w2 = _worker_pid(conf)
        st = guard.tick(cfg("PHP 8.5.12 (fpm-fcgi)"), "ENFORCE", corr, True)
        p, executed = kills(st)
        check("live/patched: census PATCHED", p["census"] == "PATCHED")
        check("live/patched: no kill executed", len(executed) == 0)
        time.sleep(0.3)
        check("live/patched: worker unchanged", _worker_pid(conf) == w2)
    finally:
        for proc in (fpm_proc, canary):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    test_detector()
    test_live()
    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    sys.exit(0 if ok else 1)
