#!/usr/bin/env python3
"""phpwarden shield stage 1: library, policy, matcher, and the real PHP agent."""
import http.client, json, os, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from phpwarden.vulndb import Feed  # noqa: E402
from phpwarden.shield import library, matcher, policy as pol, report  # noqa: E402

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and bool(cond)

feed = Feed.bundled()
AGENT = ROOT / "integrations/php-shield/phpwarden-shield.php"
ROUTER = ROOT / "integrations/php-shield/tests/router.php"

# ---- library examples (Python matcher)
bad = [(e["id"], "pos") for e in library.LIBRARY for r in e["pos"] if not matcher.match_rule(e, r)] + \
      [(e["id"], "neg") for e in library.LIBRARY for r in e["neg"] if matcher.match_rule(e, r)]
check(f"library: {len(library.LIBRARY)} rules, every exploit-shape example matches and every near-miss does not", not bad)
check("library has 25-80 entries, each with refs and a description",
      25 <= len(library.LIBRARY) <= 80 and all(e["refs"] and e["description"] for e in library.LIBRARY))

# ---- policy generation
inv = {"composer": {"phpmailer/phpmailer": "5.2.16", "phpunit/phpunit": "5.6.2"},
       "wordpress": {"core": "6.4.2", "plugins": {"litespeed-cache": "6.2"}, "themes": {}},
       "php": {"version": "8.1.2", "sapi": "fpm"}}
p = pol.build_policy(inv, feed)
ids = {r["id"] for r in p["rules"]}
check("policy: exploited vulnerabilities that are installed are included",
      {"phpmailer-sender-injection", "phpunit-eval-stdin", "litespeed-cache-role-cookie"} <= ids)
check("policy: components that are not installed are not", "wp-file-manager-connector" not in ids and "thinkphp-invokefunction" not in ids)
check("policy: engine CVEs for another SAPI / fixed branch are not included", "php-cgi-best-fit-argument-injection" not in ids)
check("policy: every rule starts in log mode, policy mode log", p["mode"] == "log" and all(r["mode"] == "log" for r in p["rules"]))
check("policy: serialized-object rule included because phpunit (gadget chain) is installed", "generic-serialized-object-gadget" in ids)
inv2 = json.loads(json.dumps(inv)); inv2["composer"]["phpmailer/phpmailer"] = "6.9.1"; inv2["wordpress"]["plugins"]["litespeed-cache"] = "6.5"
ids2 = {r["id"] for r in pol.build_policy(inv2, feed)["rules"]}
check("policy: upgrading past the fix drops the rule", "phpmailer-sender-injection" not in ids2 and "litespeed-cache-role-cookie" not in ids2)
inv3 = {"composer": {}, "wordpress": {}, "php": {"version": "8.3.99", "sapi": "fpm"}}
ids3 = {r["id"] for r in pol.build_policy(inv3, feed)["rules"]}
check("policy: no gadget package -> no serialized-object rule", "generic-serialized-object-gadget" not in ids3)
lit = next(r for r in p["rules"] if r["id"] == "phpunit-eval-stdin")
check("policy: rules are scoped to the component's own entry points", "eval-stdin" in lit.get("path", ""))
skipped = {s["id"]: s["reason"] for s in pol.build_policy(inv2, feed)["skipped"]}
check("policy: the reason a rule was left out is recorded", "fixed" in skipped.get("phpmailer-sender-injection", ""))

# ---- promotion
pp = json.loads(json.dumps(p))
_, rep = pol.promote(pp, {}, operator_ack=False)
check("promote: refused without operator acknowledgement", not rep["promoted"] and pp["mode"] == "log")
_, rep = pol.promote(pp, {}, operator_ack=True, now=p["created"] + 3 * 86400)
check("promote: refused before 7 days of burn-in", not rep["promoted"])
_, rep = pol.promote(pp, {"noisy_rules": ["generic-traversal-to-secrets"]}, operator_ack=True, now=p["created"] + 8 * 86400)
check("promote: after burn-in with ack, non-noisy rules block; noisy rules are refused",
      "phpunit-eval-stdin" in rep["promoted"] and any(r["id"] == "generic-traversal-to-secrets" for r in rep["refused"])
      and pp["mode"] == "enforce")

# ---- the real PHP agent
php = shutil.which("php")
if not php:
    print("SKIP php not installed: PHP agent tests not run")
else:
    tmp = Path(tempfile.mkdtemp(prefix="pwshield-"))
    agent_dir = tmp / "agent"; agent_dir.mkdir()
    shutil.copy(AGENT, agent_dir / "phpwarden-shield.php")
    logf = tmp / "shield.log"

    def free_port():
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close(); return port

    def start(policy_obj, env_extra=None):
        polf = tmp / "policy.json"
        if isinstance(policy_obj, str):
            polf.write_text(policy_obj)
        else:
            policy_obj = dict(policy_obj); policy_obj["log"] = {"path": str(logf), "max_bytes": policy_obj.get("log", {}).get("max_bytes", 5000000)}
            polf.write_text(json.dumps(policy_obj))
        port = free_port()
        env = dict(os.environ, PHPWARDEN_SHIELD_POLICY=str(polf), **(env_extra or {}))
        proc = subprocess.Popen([php, "-d", f"auto_prepend_file={agent_dir / 'phpwarden-shield.php'}",
                                 "-S", f"127.0.0.1:{port}", str(ROUTER)], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
            except OSError:
                time.sleep(0.05)
        return proc, port

    def send(port, req):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        h = dict(req.get("headers") or {})
        if req.get("cookies"):
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in req["cookies"].items())
        body, ctype = matcher.wire(req)             # multipart when the example uploads files
        if body:
            h["Content-Type"] = ctype
        c.putrequest(req.get("method", "GET"), req["uri"].replace(" ", "%20"), skip_accept_encoding=True)
        for k, v in h.items():
            c.putheader(k, v)
        if body:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body or None)
        r = c.getresponse(); data = r.read().decode("utf-8", "replace"); c.close()
        return r.status, data

    def log_lines():
        return [json.loads(l) for l in logf.read_text().splitlines()] if logf.exists() else []

    full = {"version": 1, "mode": "log", "budget_ms": 50, "rules": [
        {"id": e["id"], "cve": e.get("cve"), "mode": "log", **({"path": e["path"]} if e.get("path") else {}),
         "all": e.get("all", [])} for e in library.LIBRARY]}

    proc, port = start(full)
    try:
        agree, miss = 0, []
        for e in library.LIBRARY:
            for r in e["pos"]:
                logf.unlink(missing_ok=True)
                st, body = send(port, r)
                got = {x["rule"] for x in log_lines()}
                if st == 200 and body == "ok" and e["id"] in got:
                    agree += 1
                else:
                    miss.append((e["id"], st, sorted(got)))
        check(f"agent (log mode): every exploit-shape example is logged and none is blocked ({agree} requests)", not miss)
        if miss: print("   ", miss[:6])
        fp = []
        for e in library.LIBRARY:
            for r in e["neg"]:
                logf.unlink(missing_ok=True)
                send(port, r)
                if any(x["rule"] == e["id"] for x in log_lines()):
                    fp.append(e["id"])
        check("agent: near-miss examples are not logged by their rule", not fp)
        if fp: print("   ", fp)
        logf.unlink(missing_ok=True)
        send(port, {"method": "POST", "uri": "/contact.php", "ctype": "application/x-www-form-urlencoded",
                    "body": "password=hunter2&token=" + "A" * 60 + "&file=php://filter/resource=" + "B" * 300})
        txt = logf.read_text() if logf.exists() else ""
        check("log redaction: no secret values, long values cut, no full body",
              txt and "hunter2" not in txt and "A" * 40 not in txt and "B" * 200 not in txt
              and all(len(x["excerpt"]) <= 130 for x in log_lines()))
    finally:
        proc.terminate(); proc.wait()

    # block mode only for promoted rules
    enf = json.loads(json.dumps(full)); enf["mode"] = "enforce"
    for r in enf["rules"]:
        if r["id"] == "phpunit-eval-stdin":
            r["mode"] = "block"
    proc, port = start(enf)
    try:
        st1, b1 = send(port, library.LIBRARY[[e["id"] for e in library.LIBRARY].index("phpunit-eval-stdin")]["pos"][0])
        st2, b2 = send(port, {"uri": "/index.php?page=php://filter/convert.base64-encode/resource=index"})
        check("enforce: a promoted rule blocks (403)", st1 == 403 and "blocked" in b1)
        check("enforce: a rule still in log mode does not block", st2 == 200 and b2 == "ok")
    finally:
        proc.terminate(); proc.wait()
    log_mode_block = json.loads(json.dumps(enf)); log_mode_block["mode"] = "log"
    proc, port = start(log_mode_block)
    try:
        st, _ = send(port, {"method": "POST", "uri": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "body": "x", "ctype": "text/plain"})
        check("a block rule in a policy whose mode is log never blocks", st == 200)
    finally:
        proc.terminate(); proc.wait()

    # fail-open and kill switches
    for name, polobj in (("malformed policy", "{not json"), ("missing rules", json.dumps({"version": 1})),
                         ("rule that throws inside matching", json.dumps({"mode": "enforce", "rules": [
                             {"id": "boom", "mode": "block", "path": ["not", "a", "string"], "all": []}]}))):
        proc, port = start(polobj)
        try:
            st, b = send(port, {"uri": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"})
            check(f"fail open: {name} -> site works", st == 200 and b == "ok")
        finally:
            proc.terminate(); proc.wait()
    proc, port = start(enf, {"PHPWARDEN_SHIELD": "off"})
    try:
        st, _ = send(port, {"method": "POST", "uri": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "body": "x", "ctype": "text/plain"})
        check("kill switch: PHPWARDEN_SHIELD=off disables blocking", st == 200)
    finally:
        proc.terminate(); proc.wait()
    (agent_dir / "phpwarden-shield.off").write_text("")
    proc, port = start(enf)
    try:
        st, _ = send(port, {"method": "POST", "uri": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "body": "x", "ctype": "text/plain"})
        check("kill switch: phpwarden-shield.off file disables blocking", st == 200)
    finally:
        proc.terminate(); proc.wait()
        (agent_dir / "phpwarden-shield.off").unlink()

    # rotation
    small = json.loads(json.dumps(full)); small["log"] = {"max_bytes": 600}
    logf.unlink(missing_ok=True); Path(str(logf) + ".1").unlink(missing_ok=True)
    proc, port = start(small)
    try:
        for i in range(12):
            send(port, {"uri": f"/download.php?f=../../wp-config.php&n={i}"})
        check("log rotates at the size cap (one previous file kept)",
              Path(str(logf) + ".1").exists() and logf.stat().st_size < 2000)
    finally:
        proc.terminate(); proc.wait()

    # report
    logf.unlink(missing_ok=True)
    proc, port = start(full)
    try:
        for i in range(25):
            send(port, {"uri": f"/p{i}/x.php?f=../../.env"})
    finally:
        proc.terminate(); proc.wait()
    lines = logf.read_text().splitlines()
    s = report.summarize(lines)
    check("report: hits counted per rule", s["rules"] and s["rules"][0]["rule"] == "generic-traversal-to-secrets" and s["rules"][0]["hits"] == 25)
    many = [json.dumps({"rule": "r1", "path": f"/page{i}", "ip": f"203.0.113.{i}", "action": "log"}) for i in range(30)]
    check("report: a rule spread across many paths and clients is flagged noisy", report.summarize(many)["noisy_rules"] == ["r1"])

    # ---- rate limits
    def send_h(port, req):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        body = (req.get("body") or "").encode()
        c.putrequest(req.get("method", "GET"), req["uri"], skip_accept_encoding=True)
        for k, v in (req.get("headers") or {}).items():
            c.putheader(k, v)
        if body:
            c.putheader("Content-Type", "application/x-www-form-urlencoded"); c.putheader("Content-Length", str(len(body)))
        c.endheaders(body or None)
        r = c.getresponse(); d = r.read().decode(); c.close()
        return r.status, r.getheader("Retry-After"), d

    store = tmp / "lstore"
    login = {"method": "POST", "uri": "/wp-login.php", "body": "log=admin&pwd=x"}
    def lpol(mode="log", lmode="log", window=2, extra=None):
        return {"version": 1, "mode": mode, "budget_ms": 50, "rules": [],
                "limits": [{"name": "wp-login", "kind": "client", "method": ["POST"], "path": r"/wp-login\.php$",
                            "max": 3, "window_s": window, "mode": lmode}],
                "limits_store": {"backend": "file", "dir": str(store)}, **(extra or {})}

    wp_lim = [l["name"] for l in pol.build_policy({"wordpress": {"core": "6.4.2"}}, feed)["limits"]]
    lv_lim = [l["name"] for l in pol.build_policy({"composer": {"laravel/framework": "10.0.0"}}, feed)["limits"]]
    check("limits: WordPress gets login/xmlrpc/reset limits, Laravel gets login; all mode log",
          {"wp-login", "xmlrpc", "xmlrpc-multicall", "wp-password-reset"} <= set(wp_lim) and "laravel-login" in lv_lim
          and all(l["mode"] == "log" for l in pol.build_policy({"wordpress": {"core": "6.4.2"}}, feed)["limits"]))
    check("limits: build_policy(limits=False) adds none", pol.build_policy({"wordpress": {"core": "6.4.2"}}, feed, limits=False)["limits"] == [])
    bp = pol.build_policy(inv, feed)
    check("limits: burst guard covers the rule-scoped paths", any(l["kind"] == "burst" and "eval-stdin" in l["path"] for l in bp["limits"]))

    logf.unlink(missing_ok=True); shutil.rmtree(store, ignore_errors=True)
    proc, port = start(lpol(mode="log"))
    try:
        st = [send_h(port, login)[0] for _ in range(8)]
        check("limits: log mode never blocks (8 login POSTs over a max of 3 all 200)", st == [200] * 8)
        check("limits: log mode records limit:wp-login with a count, not the body",
              any(x["rule"] == "limit:wp-login" and "max 3" in x["excerpt"] and "pwd" not in json.dumps(x) for x in log_lines()))
        check("limits: file store works without APCu", store.is_dir() and any(store.iterdir()))
    finally:
        proc.terminate(); proc.wait()

    shutil.rmtree(store, ignore_errors=True)
    proc, port = start(lpol(mode="enforce", lmode="block"))
    try:
        st = [send_h(port, login) for _ in range(5)]
        check("limits: promoted limit returns 429 with Retry-After after the threshold",
              [x[0] for x in st[:3]] == [200] * 3 and st[3][0] == 429 and st[3][1] and int(st[3][1]) >= 1
              and "Too many requests" in st[3][2])
        check("limits: GETs to the same path are not counted", send_h(port, {"uri": "/wp-login.php"})[0] == 200)
        time.sleep(4.2)
        check("limits: the limit resets after the window", send_h(port, login)[0] == 200)
    finally:
        proc.terminate(); proc.wait()

    bad_store = tmp / "ro"; bad_store.mkdir(exist_ok=True); os.chmod(bad_store, 0o500)
    logf.unlink(missing_ok=True); Path(str(logf) + ".nostore").unlink(missing_ok=True)
    rp = lpol(mode="enforce", lmode="block"); rp["limits_store"] = {"backend": "file", "dir": str(bad_store / "x")}
    proc, port = start(rp)
    try:
        st = [send_h(port, login)[0] for _ in range(6)]
        un = [x for x in log_lines() if x["rule"] == "limit:_store_unavailable"]
        check("limits: unwritable store disables limits, requests pass, logged once", st == [200] * 6 and len(un) == 1)
        check("report: store-unavailable surfaced", report.summarize(logf.read_text().splitlines())["limits_store_unavailable"])
    finally:
        proc.terminate(); proc.wait(); os.chmod(bad_store, 0o700)

    for cidrs, want in ((["10.0.0.0/8"], "127.0.0.1"), (["127.0.0.0/8"], "198.51.100.7"), (["::1/128", "127.0.0.1/32"], "198.51.100.7")):
        logf.unlink(missing_ok=True); shutil.rmtree(store, ignore_errors=True)
        proc, port = start(lpol(extra={"trust_proxy": cidrs}))
        try:
            for _ in range(4):
                send_h(port, dict(login, headers={"X-Forwarded-For": "203.0.113.9, 198.51.100.7"}))
            ips = {x["ip"] for x in log_lines()}
        finally:
            proc.terminate(); proc.wait()
        check(f"trust_proxy {cidrs}: client IP is {want}", ips == {want})
    logf.unlink(missing_ok=True); shutil.rmtree(store, ignore_errors=True)
    proc, port = start(lpol(extra={"trust_proxy": True}))
    try:
        for _ in range(4):
            send_h(port, dict(login, headers={"X-Forwarded-For": "198.51.100.7", "CF-Connecting-IP": "198.51.100.8"}))
        check("trust_proxy true (not a CIDR list) trusts nothing: spoofed XFF ignored", {x["ip"] for x in log_lines()} == {"127.0.0.1"})
    finally:
        proc.terminate(); proc.wait()
    logf.unlink(missing_ok=True); shutil.rmtree(store, ignore_errors=True)
    proc, port = start(lpol(extra={"trust_proxy": ["127.0.0.0/8"]}))
    try:
        for _ in range(4):
            send_h(port, dict(login, headers={"CF-Connecting-IP": "198.51.100.8", "X-Forwarded-For": "1.2.3.4"}))
        check("trust_proxy: CF-Connecting-IP preferred from a trusted peer", {x["ip"] for x in log_lines()} == {"198.51.100.8"})
    finally:
        proc.terminate(); proc.wait()

    shutil.rmtree(store, ignore_errors=True)
    proc, port = start(lpol(mode="enforce", lmode="block"), {"PHPWARDEN_SHIELD": "off"})
    try:
        check("limits: kill switch disables limits", [send_h(port, login)[0] for _ in range(6)] == [200] * 6)
    finally:
        proc.terminate(); proc.wait()

    burst = {"version": 1, "mode": "enforce", "budget_ms": 50, "rules": [],
             "limits": [{"name": "rule-path-burst", "kind": "burst", "path": r"/vendor/x\.php$|/y\.php$", "max": 20, "window_s": 60, "mode": "block"}],
             "limits_store": {"backend": "file", "dir": str(store)}}
    shutil.rmtree(store, ignore_errors=True)
    proc, port = start(burst)
    try:
        a = [send_h(port, {"uri": "/vendor/x.php"})[0] for _ in range(22)]
        b = send_h(port, {"uri": "/y.php"})[0]
        check("limits: burst guard trips on >20/min to one scoped path, per path", a[:20] == [200] * 20 and a[21] == 429 and b == 200)
    finally:
        proc.terminate(); proc.wait()

    # latency with limits (file store)
    lat = {"version": 1, "mode": "log", "budget_ms": 50, "rules": full["rules"],
           "limits": pol.build_policy({"wordpress": {"core": "6.4.2"}}, feed)["limits"],
           "limits_store": {"backend": "file", "dir": str(store)}}
    def timed(policy_obj, n=300):
        proc, port = start(policy_obj) if policy_obj else (None, None)
        if policy_obj is None:
            port = free_port()
            proc = subprocess.Popen([php, "-S", f"127.0.0.1:{port}", str(ROUTER)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.4)
        try:
            ts = []
            for i in range(n):
                t = time.perf_counter(); send_h(port, {"method": "POST", "uri": "/wp-login.php", "body": f"log=u{i}&pwd=x"}); ts.append(time.perf_counter() - t)
            ts.sort(); return ts[n // 2] * 1000, ts[int(n * .95)] * 1000
        finally:
            proc.terminate(); proc.wait()
    base = timed(None); withl = timed(lat)
    print(f"  latency login POST, php -S: no shield p50 {base[0]:.2f} ms p95 {base[1]:.2f} ms; "
          f"shield+limits p50 {withl[0]:.2f} ms p95 {withl[1]:.2f} ms")
    check("limits: added p50 latency under 5 ms", withl[0] - base[0] < 5)

    lim_lines = [json.dumps({"rule": "limit:wp-login", "path": "/wp-login.php", "ip": f"203.0.113.{i}", "action": "log"}) for i in range(12)]
    one = [json.dumps({"rule": "limit:xmlrpc", "path": "/xmlrpc.php", "ip": "198.51.100.1", "action": "log"})] * 50
    sm = report.summarize(lim_lines + one)
    check("report: limits listed with distinct clients; a limit tripping for many clients is noisy, one hammering client is not",
          {l["limit"]: l["distinct_clients"] for l in sm["limits"]} == {"wp-login": 12, "xmlrpc": 1}
          and "limit:wp-login" in sm["noisy_rules"] and "limit:xmlrpc" not in sm["noisy_rules"])
    pl = pol.build_policy({"wordpress": {"core": "6.4.2"}}, feed)
    _, rep = pol.promote(pl, sm, operator_ack=True, now=pl["created"] + 8 * 86400)
    check("promote: limits promoted the same way; noisy limit refused",
          "limit:xmlrpc" in rep["promoted"] and any(r["id"] == "limit:wp-login" for r in rep["refused"])
          and next(l for l in pl["limits"] if l["name"] == "xmlrpc")["mode"] == "block")

    # lint on other PHP versions
    if shutil.which("docker"):
        for v in ("7.4", "8.0", "8.3"):
            r = subprocess.run(["docker", "run", "--rm", "-v", f"{AGENT.parent}:/a:ro", f"php:{v}-cli", "php", "-l", "/a/phpwarden-shield.php"],
                               capture_output=True, text=True, timeout=300)
            check(f"lint php:{v}", r.returncode == 0 and "No syntax errors" in r.stdout)
    else:
        print("SKIP docker not available: lint on 7.4/8.0/8.3 not run")

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
