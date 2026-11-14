#!/usr/bin/env python3
"""Score the WAF benchmark: three matchers over the benign and attack corpora.

  evaluate.py <repo root> <outdir>

  replay      `phpwarden rules --replay` (the log matcher in detect.py)
  nginx       the generated nginx rules, applied as nginx would: each
              `if ($request_uri ~* "RX")` regex, case-insensitive, against the
              raw request target
  modsec      the generated ModSecurity rules, emulated: each `@rx` against the
              raw target, the percent-decoded target and each decoded argument
              value (REQUEST_URI_RAW|REQUEST_URI|ARGS). An emulation, not a
              run of ModSecurity itself.
"""
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, unquote


def main(argv):
    repo, out = Path(argv[1]), Path(argv[2])
    sys.path.insert(0, str(repo / "src"))
    from phpwarden import rules
    from phpwarden.detect import SignatureScanner
    from phpwarden.vulndb import Feed

    # The curated base feed: its engine CVEs carry the request signatures that
    # the next feed build ships (the bundled feed is built from it).
    feed = Feed.load(repo / "feedbuilder" / "base" / "php-cve-feed.base.json")
    bundled = Feed.bundled()
    sigs = rules._request_sigs(feed)
    by_cve = defaultdict(list)
    for cve, pat, _ in sigs:
        by_cve[cve].append(pat)
    print("== Coverage ==")
    print(f"engine CVEs in the feed: {len(feed.cves)}; with a request signature: {len(by_cve)} "
          f"({', '.join(f'{c} {p}' for c, p in by_cve.items())})")
    print(f"for scale, the bundled feed {bundled.feed_version} has {len(bundled.cves)} engine CVEs, "
          f"{len(bundled.composer)} Composer and {len(bundled.wp)} WordPress advisories; "
          f"none of the Composer or WordPress ones has a request signature")

    nginx_rx = [(m.group(1), re.compile(m.group(2), re.I)) for m in re.finditer(
        r'# (CVE-[\d-]+):[^\n]*\nif \(\$request_uri ~\* "([^"]+)"\)', rules.generate(feed, "nginx"))]
    modsec_rx = [(m.group(2), re.compile(m.group(1))) for m in re.finditer(
        r'"@rx ([^"]+)" "id:\d+[^\n]*?tag:\'(CVE-[\d-]+)\'', rules.generate(feed, "modsecurity"))]
    scanner = SignatureScanner(feed)

    def m_replay(line, target):
        return {h.cve_id for h in scanner.scan_line(line, "access", 0) if h.kind == "request-signature"}

    def m_nginx(line, target):
        return {c for c, rx in nginx_rx if rx.search(target)}

    def m_modsec(line, target):
        fields = [target, unquote(target, errors="replace")]
        fields += [v for _, v in parse_qsl(target.partition("?")[2], keep_blank_values=True, errors="replace")]
        return {c for c, rx in modsec_rx if any(rx.search(f) for f in fields)}

    matchers = [("replay", m_replay), ("nginx", m_nginx), ("modsec", m_modsec)]

    def target_of(line):
        return line.split('"')[1].split(" ")[1]

    print("\n== Benign traffic: false positives ==")
    lines = (out / "benign.log").read_text().splitlines()
    cats = {}
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import corpus
    inv = {v: k for k, v in corpus.ADDR.items()}
    total = Counter(inv[ln.split(" ")[0]] for ln in lines)
    fp = {name: defaultdict(list) for name, _ in matchers}
    for ln in lines:
        cat, tgt = inv[ln.split(" ")[0]], target_of(ln)
        for name, fn in matchers:
            hit = fn(ln, tgt)
            if hit:
                fp[name][cat].append((tgt, sorted(hit)))
    print(f"{'category':<18}{'requests':>9}" + "".join(f"{n:>9}" for n, _ in matchers))
    for cat in corpus.CATS:
        print(f"{cat:<18}{total[cat]:>9}" + "".join(f"{len(fp[n][cat]):>9}" for n, _ in matchers))
    print(f"{'TOTAL':<18}{len(lines):>9}" + "".join(f"{sum(len(v) for v in fp[n].values()):>9}" for n, _ in matchers))
    for name, _ in matchers:
        n = sum(len(v) for v in fp[name].values())
        print(f"  {name}: {n}/{len(lines)} benign requests would be blocked ({n / len(lines) * 100:.2f}%)")
    print("\nExamples of blocked benign requests (up to 3 per category and matcher):")
    for name, _ in matchers:
        for cat in corpus.CATS:
            for tgt, hit in fp[name][cat][:3]:
                print(f"  [{name}] {cat}: {tgt[:110]}  -> {', '.join(hit)}")
    (out / "false-positives.tsv").write_text("\n".join(
        f"{name}\t{cat}\t{','.join(hit)}\t{tgt}" for name, _ in matchers for cat in corpus.CATS
        for tgt, hit in fp[name][cat]) + "\n")

    print("\n== Attack request shapes: detection ==")
    attacks = [ln.split("\t") for ln in (out / "attacks.tsv").read_text().splitlines()]
    alog = (out / "attacks.log").read_text().splitlines()
    score = {n: Counter() for n, _ in matchers}
    per_tech = {n: defaultdict(lambda: [0, 0]) for n, _ in matchers}
    print(f"{'CVE':<16}{'variant':<46}{'technique':<22}" + "".join(f"{n:>8}" for n, _ in matchers))
    for (cve, variant, tech, tgt), ln in zip(attacks, alog):
        row = ""
        for name, fn in matchers:
            ok = cve in fn(ln, tgt)
            score[name][cve] += ok
            per_tech[name][tech][0] += ok
            per_tech[name][tech][1] += 1
            row += f"{'yes' if ok else 'MISS':>8}"
        print(f"{cve:<16}{variant[:44]:<46}{tech:<22}{row}")
    n_cve = Counter(a[0] for a in attacks)
    print("\nPer CVE (detected / shapes):")
    for cve in n_cve:
        print(f"  {cve:<16}" + "  ".join(f"{n} {score[n][cve]}/{n_cve[cve]}" for n, _ in matchers))
    print("Per technique (detected / shapes):")
    for tech in sorted({a[2] for a in attacks}):
        print(f"  {tech:<22}" + "  ".join(f"{n} {per_tech[n][tech][0]}/{per_tech[n][tech][1]}" for n, _ in matchers))
    print(f"Overall: " + "  ".join(f"{n} {sum(score[n].values())}/{len(attacks)}" for n, _ in matchers))


if __name__ == "__main__":
    main(sys.argv)
