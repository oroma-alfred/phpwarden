#!/usr/bin/env python3
"""phpwarden shield benchmark: false positives, true positives, latency.

  bench.py <repo> <benign.log from bench/waf-2026-11> <workdir>

Nothing is sent to any other host: requests go to `php -S` on 127.0.0.1.
"""
import http.client, json, os, random, shutil, socket, statistics, subprocess, sys, tempfile, time
from pathlib import Path
from urllib.parse import quote, urlencode

REPO, BENIGN, W = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
sys.path.insert(0, str(REPO / "src"))
from phpwarden.shield import library, matcher  # noqa: E402

W.mkdir(parents=True, exist_ok=True)
PHP = shutil.which("php")
R = random.Random(20261114)
AGENT = REPO / "integrations/php-shield/phpwarden-shield.php"
ROUTER = REPO / "integrations/php-shield/tests/router.php"


def full_policy(pad_to=None):
    rules = [{"id": e["id"], "cve": e.get("cve"), "mode": "log", **({"path": e["path"]} if e.get("path") else {}),
              "all": e.get("all", [])} for e in library.LIBRARY]
    if pad_to:
        base = list(rules)
        i = 0
        while len(rules) < pad_to:
            r = dict(base[i % len(base)]); r["id"] = f"{r['id']}-copy{i}"; rules.append(r); i += 1
    return {"version": 1, "mode": "log", "budget_ms": 50, "rules": rules}


# ---------------------------------------------------------------- benign requests
def benign_gets():
    out = []
    for line in BENIGN.read_text(errors="replace").splitlines():
        try:
            req = line.split('"')[1]
            method, target, _ = req.split(" ")
        except (IndexError, ValueError):
            continue
        out.append({"method": method, "uri": target, "cat": "get:" + line.split(" ")[0]})
    return out


WORDS = "hello order invoice shipping blue shoes size 42 thanks question about my account please call me back".split()
UNI = ["información", "categoría", "Zürich", "日本語", "한국어", "café ☕", "naïve façade", "São Paulo", "Łódź"]


def benign_posts():
    out = []
    form = "application/x-www-form-urlencoded"
    for i in range(400):
        msg = " ".join(R.choice(WORDS) for _ in range(R.randint(3, 40)))
        if R.random() < 0.3:
            msg += "\n" + R.choice(UNI) + "\nline two {curly} [square] <b>bold</b> 50% off & more"
        if R.random() < 0.1:
            msg += " my config has auto_prepend_file set, and allow_url_include is off; is ../ in a path bad?"
        body = urlencode({"your-name": "Anna-Maria O'Neil", "your-email": f"anna.{i}@example.com",
                          "your-subject": R.choice(WORDS), "your-message": msg, "_wpcf7": "42", "_wpnonce": "a1b2c3d4e5"})
        out.append({"method": "POST", "uri": "/wp-json/contact-form-7/v1/contact-forms/42/feedback", "body": body, "ctype": form, "cat": "post:contact-form"})
    for i in range(300):
        body = urlencode({"comment": " ".join(R.choice(WORDS) for _ in range(20)) + " https://example.com/page?a=1&b=2",
                          "author": R.choice(UNI), "email": f"c{i}@example.org", "url": "https://blog.example/", "comment_post_ID": str(i), "comment_parent": "0"})
        out.append({"method": "POST", "uri": "/wp-comments-post.php", "body": body, "ctype": form, "cat": "post:comment"})
    for i in range(300):
        body = urlencode({"billing_first_name": R.choice(UNI), "billing_last_name": "García-López", "billing_address_1": "Calle Mayor 5, 3º-2ª",
                          "billing_email": f"b{i}@example.com", "payment_method": "stripe", "woocommerce-process-checkout-nonce": "abc123",
                          "order_comments": "Leave at the door -- thanks!", "_wp_http_referer": "/checkout/?wc-ajax=update_order_review"})
        out.append({"method": "POST", "uri": "/?wc-ajax=checkout", "body": body, "ctype": form, "cat": "post:checkout"})
    for i in range(300):
        doc = {"title": R.choice(UNI) + " " + R.choice(WORDS), "content": "<!-- wp:paragraph --><p>" + " ".join(R.choice(WORDS) for _ in range(30)) + "</p><!-- /wp:paragraph -->",
               "status": "draft", "meta": {"layout": {"rows": [1, 2], "template": "{{title}} – {{date}}"}}, "tags": [1, 2, 3]}
        out.append({"method": "POST", "uri": f"/wp-json/wp/v2/posts/{i}", "body": json.dumps(doc), "ctype": "application/json", "cat": "post:rest-json",
                    "cookies": {"wordpress_logged_in_abc": "admin%7C1730000000%7Cxyz%7Cdef", "wp-settings-1": "libraryContent%3Dbrowse"}})
    for i in range(200):
        body = urlencode({"log": f"user{i}", "pwd": "S3cret!pass../..", "rememberme": "forever", "redirect_to": "/wp-admin/", "testcookie": "1"})
        out.append({"method": "POST", "uri": "/wp-login.php", "body": body, "ctype": form, "cat": "post:login"})
    for i in range(300):
        body = json.dumps({"query": "mutation { addToCart(id: %d, qty: 2) { ok } }" % i, "variables": {"note": R.choice(UNI)}})
        out.append({"method": "POST", "uri": "/graphql", "body": body, "ctype": "application/json", "cat": "post:graphql",
                    "cookies": {"woocommerce_cart_hash": "a3f9c2", "wp_woocommerce_session_x": "1%7C%7C1730%7C%7Cabc", "laravel_session": "eyJpdiI6IjEyMyJ9"}})
    for i in range(200):
        body = urlencode({"_token": "x" * 40, "email": f"l{i}@example.com", "password": "secret", "data[items][0][name]": R.choice(UNI),
                          "data[items][0][qty]": "3", "filter[status]": "open"})
        out.append({"method": "POST", "uri": "/orders/store", "body": body, "ctype": form, "cat": "post:laravel-form"})
    return out


def evaluate_python(reqs, policy):
    fps = []
    for r in reqs:
        hits = matcher.evaluate(policy, r)
        if hits:
            fps.append((r.get("cat"), r["uri"][:120], [h[0] for h in hits]))
    return fps


# ---------------------------------------------------------------- php helpers
def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def serve(policy=None, shield=True):
    port = free_port()
    args = [PHP]
    env = dict(os.environ)
    if shield:
        polf = W / "policy.json"; logf = W / "shield.log"
        policy = dict(policy); policy["log"] = {"path": str(logf), "max_bytes": 50_000_000}
        polf.write_text(json.dumps(policy))
        env["PHPWARDEN_SHIELD_POLICY"] = str(polf)
        args += ["-d", f"auto_prepend_file={AGENT}"]
    proc = subprocess.Popen(args + ["-S", f"127.0.0.1:{port}", str(ROUTER)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
        except OSError:
            time.sleep(0.05)
    return proc, port


def send(port, r):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = dict(r.get("headers") or {})
    if r.get("cookies"):
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in r["cookies"].items())
    body = (r.get("body") or "").encode()
    c.putrequest(r.get("method", "GET"), r["uri"].replace(" ", "%20"), skip_accept_encoding=True)
    for k, v in h.items():
        c.putheader(k, v)
    if body:
        c.putheader("Content-Type", r.get("ctype", "application/octet-stream")); c.putheader("Content-Length", str(len(body)))
    c.endheaders(body or None)
    resp = c.getresponse(); resp.read(); c.close()
    return resp.status


def main():
    gets, posts = benign_gets(), benign_posts()
    policy = full_policy()
    print(f"policy: {len(policy['rules'])} rules (the whole library, every rule enabled: worst case for false positives)")
    fp_get, fp_post = evaluate_python(gets, policy), evaluate_python(posts, policy)
    cats = {}
    for r in gets + posts:
        cats[r["cat"].split(":")[0] + ":" + (r["cat"].split(":")[1] if r["cat"].startswith("post") else "waf-corpus")] = cats.get(
            r["cat"].split(":")[0] + ":" + (r["cat"].split(":")[1] if r["cat"].startswith("post") else "waf-corpus"), 0) + 1
    print("\n== False positives on benign traffic (Python matcher, same rules as the agent)")
    for k, n in sorted(cats.items()):
        print(f"  {k:<22} {n:>6}")
    print(f"  benign requests: {len(gets) + len(posts)}  matched by any rule: {len(fp_get) + len(fp_post)}")
    for f in (fp_get + fp_post)[:30]:
        print("   FP", f)

    if not PHP:
        print("\nphp not installed: agent cross-check and latency not measured")
        return
    # cross-check a sample through the real agent
    sample = R.sample(gets, 1500) + posts
    proc, port = serve(policy)
    try:
        logf = W / "shield.log"; logf.unlink(missing_ok=True)
        for r in sample:
            send(port, r)
        agent_hits = len(logf.read_text().splitlines()) if logf.exists() else 0
    finally:
        proc.terminate(); proc.wait()
    print(f"\n== Real PHP agent on {len(sample)} benign requests (1,500 sampled GETs + all {len(posts)} POSTs): {agent_hits} logged match(es)")

    # true positives per rule through the agent
    proc, port = serve(policy)
    tp = {}
    try:
        for e in library.LIBRARY:
            n = 0
            for r in e["pos"]:
                logf.unlink(missing_ok=True)
                send(port, r)
                lines = [json.loads(l) for l in logf.read_text().splitlines()] if logf.exists() else []
                n += any(x["rule"] == e["id"] for x in lines)
            tp[e["id"]] = (n, len(e["pos"]), e.get("cve") or "-")
    finally:
        proc.terminate(); proc.wait()
    print("\n== Exploit-shape requests logged by the matching rule (real agent)")
    for rid, (n, t, cve) in tp.items():
        print(f"  {rid:<42} {cve:<16} {n}/{t}")
    print(f"  total: {sum(v[0] for v in tp.values())}/{sum(v[1] for v in tp.values())}")

    # latency: CLI micro-benchmark of the agent's own cost
    pol50 = full_policy(pad_to=50)
    (W / "pol50.json").write_text(json.dumps(pol50))
    (W / "pol50.php").write_text("<?php return json_decode(" + json.dumps(json.dumps(pol50)).replace("$", "\\$") + ", true);\n")
    micro = W / "micro.php"
    micro.write_text(r'''<?php
putenv('PHPWARDEN_SHIELD_POLICY=' . $argv[1]);
$_SERVER['REQUEST_METHOD'] = $argv[2]; $_SERVER['REQUEST_URI'] = $argv[3];
$_SERVER['QUERY_STRING'] = (string)parse_url($argv[3], PHP_URL_QUERY); $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
parse_str($_SERVER['QUERY_STRING'], $_GET);
if ($argv[2] === 'POST') { parse_str('your-name=Anna&your-email=a%40example.com&your-message=hello+there+how+are+you&_wpnonce=abc', $_POST); }
$_COOKIE = array('wordpress_logged_in_x' => 'admin%7C1730', 'woocommerce_cart_hash' => 'a3f9c2');
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0'; $_SERVER['HTTP_ACCEPT'] = 'text/html';
require $argv[4];                      // defines the functions and runs once
$n = 20000; $t = hrtime(true);
for ($i = 0; $i < $n; $i++) { phpwarden_shield_run(); }
$per = (hrtime(true) - $t) / $n / 1000.0;
printf("%.1f\n", $per);
''')
    print("\n== Agent cost per request, CLI micro-benchmark (20,000 runs each, 50-rule policy)")
    for label, method, uri, pol in (("GET /blog/post-slug/?utm_source=x (policy JSON)", "GET", "/blog/post-slug/?utm_source=newsletter&page=2", "pol50.json"),
                                    ("GET, policy as .php (opcache-style)", "GET", "/blog/post-slug/?utm_source=newsletter&page=2", "pol50.php"),
                                    ("POST contact form (policy JSON)", "POST", "/wp-json/contact-form-7/v1/contact-forms/42/feedback", "pol50.json")):
        out = subprocess.run([PHP, "-d", "opcache.enable_cli=1", str(micro), str(W / pol), method, uri, str(AGENT)], capture_output=True, text=True, env=dict(os.environ, PHPWARDEN_SHIELD_POLICY=str(W / pol)))
        print(f"  {label:<52} {out.stdout.strip() or out.stderr.strip()[:80]} µs")

    # latency over HTTP: php -S with and without the shield
    reqs = [R.choice(gets) for _ in range(2000)]
    res = {}
    for label, shield in (("no shield", False), ("shield, 50 rules", True)):
        proc, port = serve(pol50, shield=shield)
        try:
            for r in reqs[:100]:
                send(port, r)                       # warm-up
            ts = []
            for r in reqs:
                t = time.perf_counter(); send(port, r); ts.append((time.perf_counter() - t) * 1000)
        finally:
            proc.terminate(); proc.wait()
        ts.sort()
        res[label] = (statistics.median(ts), ts[int(len(ts) * 0.95)])
        print(f"  HTTP {label:<18} p50 {res[label][0]:.3f} ms  p95 {res[label][1]:.3f} ms  (2,000 requests, php -S, one client)")
    print(f"  added: p50 {res['shield, 50 rules'][0] - res['no shield'][0]:+.3f} ms, p95 {res['shield, 50 rules'][1] - res['no shield'][1]:+.3f} ms")


if __name__ == "__main__":
    main()
