"""Summarise the shield agent's JSON-lines log (phpwarden-shield.log).

    summary = summarize(open("phpwarden-shield.log"))

The agent runs before the application, so it cannot see the response status.
"Noisy" therefore uses what it can see: a rule whose hits are spread across many
different paths from many different clients looks like it is matching ordinary
traffic (real exploit attempts against one component hit a handful of paths).
Such a rule is never promoted to blocking without review (policy.promote).
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict

NOISY_MIN_HITS = 20
NOISY_MIN_PATHS = 10
NOISY_MIN_CLIENTS = 10


def summarize(lines, top=10):
    by_rule = defaultdict(lambda: {"hits": 0, "blocked": 0, "cve": None, "paths": Counter(), "ips": Counter(),
                                   "first": None, "last": None})
    paths, ips = Counter(), Counter()
    total = bad = skipped_budget = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if e.get("rule") == "_budget":
            skipped_budget += 1
            continue
        total += 1
        r = by_rule[e.get("rule", "?")]
        r["hits"] += 1
        r["blocked"] += e.get("action") == "block"
        r["cve"] = r["cve"] or e.get("cve")
        r["paths"][e.get("path", "")] += 1
        r["ips"][e.get("ip", "")] += 1
        ts = e.get("ts")
        r["first"] = min(filter(None, [r["first"], ts])) if ts else r["first"]
        r["last"] = max(filter(None, [r["last"], ts])) if ts else r["last"]
        paths[e.get("path", "")] += 1
        ips[e.get("ip", "")] += 1
    rules, noisy = [], []
    for rid, r in sorted(by_rule.items(), key=lambda kv: -kv[1]["hits"]):
        is_noisy = (r["hits"] >= NOISY_MIN_HITS and len(r["paths"]) >= NOISY_MIN_PATHS
                    and len(r["ips"]) >= NOISY_MIN_CLIENTS)
        if is_noisy:
            noisy.append(rid)
        rules.append({"rule": rid, "cve": r["cve"], "hits": r["hits"], "blocked": r["blocked"],
                      "distinct_paths": len(r["paths"]), "distinct_clients": len(r["ips"]),
                      "top_paths": r["paths"].most_common(3), "first": r["first"], "last": r["last"],
                      "noisy": is_noisy})
    return {"hits": total, "unreadable_lines": bad, "budget_exceeded": skipped_budget, "rules": rules,
            "top_paths": paths.most_common(top), "top_clients": ips.most_common(top), "noisy_rules": noisy}


def to_text(s):
    out = [f"{s['hits']} hit(s); {len(s['rules'])} rule(s) matched"
           + (f"; {s['budget_exceeded']} request(s) skipped (time budget)" if s["budget_exceeded"] else "")]
    for r in s["rules"]:
        out.append(f"  {r['rule']} {r['cve'] or ''}: {r['hits']} hit(s), {r['blocked']} blocked, "
                   f"{r['distinct_paths']} path(s), {r['distinct_clients']} client(s)"
                   + ("  NOISY: review before blocking" if r["noisy"] else ""))
    if s["top_clients"]:
        out.append("  top clients: " + ", ".join(f"{ip} ({n})" for ip, n in s["top_clients"][:5]))
    return "\n".join(out)
