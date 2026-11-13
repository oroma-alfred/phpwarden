import json,collections,datetime as dt
meta={l.split("\t")[0]:l.rstrip("\n").split("\t") for l in open("withlock.tsv")}
ld={a:b for a,b in (l.rstrip("\n").split("\t") for l in open("lockdates.tsv"))}
today=dt.datetime.now(dt.timezone.utc)
R=[]
for k,m in meta.items():
    lock=json.load(open(f"locks/{k}.lock")); dev={p["name"] for p in lock.get("packages-dev") or []}
    v=json.load(open(f"scans/{k}.json"))["vulnerable"]
    age=(today-dt.datetime.fromisoformat(ld[k].replace("Z","+00:00"))).days
    def S(fs): return {"n":len(fs),"kev":[f for f in fs if f.get("known_exploited")],"hot":[f for f in fs if (f.get("epss") or 0)>=0.5 and not f.get("known_exploited")],"ch":sum(1 for f in fs if f.get("severity") in("critical","high"))}
    R.append({"k":k,"repo":m[1],"stars":int(m[2]),"age":age,"prod":S([f for f in v if f["package"] not in dev]),"dev":S([f for f in v if f["package"] in dev]),"pk":len(lock.get("packages") or [])})
def report(rs,label):
    n=len(rs); c=lambda f:sum(1 for r in rs if f(r))
    print(f"\n== {label}: {n} projects")
    print(f" any known vuln (prod deps): {c(lambda r:r['prod']['n']>0)} ({100*c(lambda r:r['prod']['n']>0)/n:.0f}%)")
    print(f" KEV in prod deps: {c(lambda r:r['prod']['kev'])}  | KEV only in dev deps: {c(lambda r:not r['prod']['kev'] and r['dev']['kev'])}")
    print(f" KEV or EPSS>=50% in prod: {c(lambda r:r['prod']['kev'] or r['prod']['hot'])}")
    tot=sum(r['prod']['n'] for r in rs); ch=sum(r['prod']['ch'] for r in rs); hot=sum(len(r['prod']['kev'])+len(r['prod']['hot']) for r in rs)
    print(f" prod findings total {tot}, critical/high {ch}, exploited-or-likely {hot}")
report(R,"all lockfiles")
act=[r for r in R if r["age"]<=365]; report(act,"lockfile updated in last 12 months")
report([r for r in R if r["age"]<=90],"lockfile updated in last 90 days")
pk=collections.Counter(); 
for r in R:
    for f in r["prod"]["kev"]: pk[(f["package"],f["cve"])]+=1
print("\nKEV in prod deps, by package/CVE:"); [print(" ",n,p,c) for (p,c),n in pk.most_common(15)]
json.dump(R,open("per_repo.json","w"),default=str,indent=1)
