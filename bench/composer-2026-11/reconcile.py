"""Second pass: Drupal publishes some advisories only as SA-CORE-* in its own repo,
which share no ID with GHSA/OSV. Pair an audit-only drupal/core SA with an
unpaired non-audit drupal/core cluster whose fixed releases are identical to the
SA's upper bounds. Pairing is one-to-one; ties are resolved in listing order."""
import json,re,sys,collections
feed=sys.argv[1]
d=json.load(open(f"results.{feed}.json"))
A=json.load(open("drupal9/audit.json"))["advisories"]["drupal/core"]
A={x["advisoryId"]:x for x in (A.values() if isinstance(A,dict) else A)}
ub=lambda s:set(re.findall(r'<\s*([0-9][0-9.]*)',s))
rows=d["drupal9"]
lone=[r for r in rows if r["pkg"]=="drupal/core" and r["src"]==["audit"]]
other=[r for r in rows if r["pkg"]=="drupal/core" and "audit" not in r["src"] and r.get("f")]
pairs=[]
for m in lone:
    sa=[i for i in m["ids"] if i.startswith("SA-")]
    if not sa: continue
    b=ub(A[sa[0]]["affectedVersions"])
    for o in other:
        if set(o["f"]["fixed"])<=b and len(set(o["f"]["fixed"])&b)>=2:
            pairs.append((sa[0],o["f"]["title"][:50])); o["src"]=sorted(set(o["src"])|{"audit"}); rows.remove(m); other.remove(o); break
# audit-side gaps: non-audit drupal clusters with a fix release matching ANY audit SA
for o in list(other):
    for sa,x in A.items():
        if sa.startswith("SA-") and set(o["f"]["fixed"])<=ub(x["affectedVersions"]) and len(set(o["f"]["fixed"]))>=2:
            pass
tot=collections.Counter()
for p,rs in d.items():
    for r in rs: tot[tuple(r["src"])]+=1
n=sum(tot.values()); s=lambda k:sum(v for t,v in tot.items() if k in t)
print(f"{feed}: paired {len(pairs)}  distinct={n}  phpwarden={s('pw')} ({100*s('pw')/n:.1f}%)  composer-audit={s('audit')} ({100*s('audit')/n:.1f}%)  osv={s('osv')} ({100*s('osv')/n:.1f}%)")
print("  combos:",dict(tot))
for a,b in pairs: print("  ",a,"==",b)
json.dump(d,open(f"final.{feed}.json","w"),indent=1)
