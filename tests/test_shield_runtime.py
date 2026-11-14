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
check("library has 25-40 entries, each with refs and a description",
      25 <= len(library.LIBRARY) <= 40 and all(e["refs"] and e["description"] for e in library.LIBRARY))

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
        body = (req.get("body") or "").encode("utf-8", "surrogateescape")
        if body:
            h["Content-Type"] = req.get("ctype") or "application/octet-stream"
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

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
