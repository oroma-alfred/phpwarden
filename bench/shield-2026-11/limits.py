#!/usr/bin/env python3
"""Rate-limit benchmark for the shield agent.

    python3 -I limits.py REPO BENIGN_LOG WORKDIR

1. The benign corpus (same requests as bench.py) replayed through the real agent
   with every default WordPress and Laravel limit plus a burst guard over every
   library rule path, spread over 300 clients the way a busy site sees them
   (a trusted local proxy passes the client in X-Forwarded-For). Expect 0 trips.
2. Abuse scenarios from one client: login brute force, xmlrpc flood,
   system.multicall, password-reset spam, a burst on a vulnerable path.
3. Latency, no shield vs shield with limits (file store), login POSTs.
Everything runs on 127.0.0.1."""
import json, sys, time
from pathlib import Path

sys.argv = [sys.argv[0], *sys.argv[1:4]]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench as B  # noqa: E402
from phpwarden.shield import library, policy as P  # noqa: E402

W = B.W / "limits"; W.mkdir(parents=True, exist_ok=True)
STORE = W / "store"


def limits_policy(mode="log", lmode="log"):
    lims = P.limits_for({"wordpress": {"core": "6.4.2"}, "composer": {"laravel/framework": "11.0.0"}},
                        [{"path": e["path"]} for e in library.LIBRARY if e.get("path")])
    for l in lims:
        l["mode"] = lmode
    return {"version": 1, "mode": mode, "budget_ms": 50, "rules": [], "limits": lims,
            "trust_proxy": ["127.0.0.0/8"], "limits_store": {"backend": "file", "dir": str(STORE)}}


def run(policy, reqs):
    import shutil
    shutil.rmtree(STORE, ignore_errors=True)
    proc, port = B.serve(policy)
    logf = B.W / "shield.log"; logf.unlink(missing_ok=True)
    try:
        st = [B.send(port, r) for r in reqs]
    finally:
        proc.terminate(); proc.wait()
    lines = [json.loads(l) for l in logf.read_text().splitlines()] if logf.exists() else []
    return st, lines


def client(r, i):
    r = dict(r); r["headers"] = dict(r.get("headers") or {}, **{"X-Forwarded-For": f"198.51.{100 + i % 300 // 250}.{i % 300 % 250}"})
    return r


def main():
    gets, posts = B.benign_gets(), B.benign_posts()
    reqs = [client(r, i) for i, r in enumerate(B.R.sample(gets, 4000) + posts)]
    B.R.shuffle(reqs)
    st, lines = run(limits_policy(), reqs)
    trips = [l for l in lines if l["rule"].startswith("limit:")]
    print(f"== Benign corpus through the agent with {len(limits_policy()['limits'])} limits, 300 clients: "
          f"{len(reqs)} requests, {len(trips)} limit trip(s)")
    for t in trips[:10]:
        print("   TRIP", t["rule"], t["path"], t["excerpt"])

    me = {"X-Forwarded-For": "203.0.113.50"}
    scen = {
        "login brute force (40 POST /wp-login.php)": [{"method": "POST", "uri": "/wp-login.php", "body": f"log=admin&pwd=p{i}", "ctype": "application/x-www-form-urlencoded", "headers": me} for i in range(40)],
        "xmlrpc flood (60 POST /xmlrpc.php)": [{"method": "POST", "uri": "/xmlrpc.php", "body": "<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>", "ctype": "text/xml", "headers": me} for _ in range(60)],
        "system.multicall (6 POSTs)": [{"method": "POST", "uri": "/xmlrpc.php", "body": "<methodCall><methodName>system.multicall</methodName></methodCall>", "ctype": "text/xml", "headers": me} for _ in range(6)],
        "password-reset spam (12 POSTs)": [{"method": "POST", "uri": "/wp-login.php?action=lostpassword", "body": "user_login=admin", "ctype": "application/x-www-form-urlencoded", "headers": me} for _ in range(12)],
        "Laravel login brute force (30 POST /login)": [{"method": "POST", "uri": "/login", "body": "email=a%40b.c&password=x", "ctype": "application/x-www-form-urlencoded", "headers": me} for _ in range(30)],
        "burst on a vulnerable path (40 GET eval-stdin.php)": [{"uri": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "headers": me} for _ in range(40)],
    }
    print("\n== Abuse scenarios, one client (log mode: trips logged; promoted: first 429 at request #)")
    for name, rs in scen.items():
        _, lines = run(limits_policy(), rs)
        names = sorted({l["rule"] for l in lines})
        st, _ = run(limits_policy("enforce", "block"), rs)
        first = next((i + 1 for i, s in enumerate(st) if s == 429), None)
        print(f"  {name:<52} logged {len(lines):>3} ({', '.join(names) or '-'}); promoted: first 429 at #{first}, {st.count(429)} x 429")

    print("\n== Latency, 2,000 login POSTs from 300 clients (php -S)")
    lat = [client({"method": "POST", "uri": "/wp-login.php", "body": f"log=u{i}&pwd=x", "ctype": "application/x-www-form-urlencoded"}, i) for i in range(2000)]
    res = {}
    for label, pol, shield in (("no shield", None, False), ("shield, limits only", limits_policy(), True)):
        import shutil
        shutil.rmtree(STORE, ignore_errors=True)
        proc, port = B.serve(pol or {}, shield=shield)
        try:
            for r in lat[:100]:
                B.send(port, r)
            ts = []
            for r in lat:
                t = time.perf_counter(); B.send(port, r); ts.append((time.perf_counter() - t) * 1000)
        finally:
            proc.terminate(); proc.wait()
        ts.sort(); res[label] = (ts[len(ts) // 2], ts[int(len(ts) * .95)])
        print(f"  {label:<22} p50 {res[label][0]:.3f} ms  p95 {res[label][1]:.3f} ms")
    a, b = res["shield, limits only"], res["no shield"]
    print(f"  added: p50 {a[0] - b[0]:+.3f} ms, p95 {a[1] - b[1]:+.3f} ms")


if __name__ == "__main__":
    main()
