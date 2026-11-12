import json,sys,urllib.request,concurrent.futures as cf
def post(u,b): return json.load(urllib.request.urlopen(urllib.request.Request(u,json.dumps(b).encode(),{"Content-Type":"application/json"}),timeout=60))
def get(u): return json.load(urllib.request.urlopen(u,timeout=60))
vcache={}
def vuln(i):
    if i not in vcache: vcache[i]=get("https://api.osv.dev/v1/vulns/"+i)
    return vcache[i]
out={}
for p in sys.argv[1:]:
    lock=json.load(open(f"{p}/composer.lock"))
    pk=[(x["name"],x["version"].lstrip("v")) for x in lock["packages"]]
    # composer audit
    au={}
    for name,advs in json.load(open(f"{p}/audit.json"))["advisories"].items():
        for a in (advs.values() if isinstance(advs,dict) else advs):
            ids={a.get("cve"),a.get("advisoryId")}|{s.get("remoteId") for s in a.get("sources",[])}
            ids={t for i in ids if i for t in str(i).replace(",", " ").split()}
            au.setdefault(name,[]).append(ids)
    # phpwarden
    pwd=json.load(open(f"{p}/pw.json"))
    pw={}
    for f in pwd["vulnerable"]:
        ids={f.get("cve"),f.get("id"),f.get("ghsa")}|set(f.get("aliases") or [])
        ids|={f"{f['package']}/{i}.yaml" for i in list(ids) if i and i[:2]=="20" and not i.startswith("CVE")}
        pw.setdefault(f["package"],[]).append({"ids":{i for i in ids if i},"f":f})
    # osv
    r=post("https://api.osv.dev/v1/querybatch",{"queries":[{"package":{"name":n,"ecosystem":"Packagist"},"version":v} for n,v in pk]})
    osv={}
    ids_needed=[(pk[k][0],v["id"]) for k,res in enumerate(r["results"]) for v in res.get("vulns",[])]
    with cf.ThreadPoolExecutor(16) as ex: list(ex.map(lambda t: vuln(t[1]), ids_needed))
    for n,i in ids_needed:
        d=vcache[i]; osv.setdefault(n,[]).append({i,*d.get("aliases",[])})
    # union of distinct real-world advisories per package: cluster id sets
    rows=[]
    for n in set(au)|set(pw)|set(osv):
        clusters=[]
        def add(src,s):
            for c in clusters:
                if c["ids"]&s: c["ids"]|=s; c["src"].add(src); return c
            c={"ids":set(s),"src":{src}}; clusters.append(c); return c
        for s in osv.get(n,[]): add("osv",s)
        for s in au.get(n,[]): add("audit",s)
        for x in pw.get(n,[]): c=add("pw",x["ids"]); c["f"]=x["f"]
        # merge pass
        merged=True
        while merged:
            merged=False
            for a in clusters:
                for b in clusters:
                    if a is not b and a["ids"]&b["ids"]:
                        a["ids"]|=b["ids"]; a["src"]|=b["src"]; a.setdefault("f",b.get("f")); clusters.remove(b); merged=True; break
                if merged: break
        for c in clusters: rows.append({"pkg":n,"ids":sorted(c["ids"]),"src":sorted(c["src"]),"f":c.get("f")})
    out[p]=rows
    tot=len(rows); s=lambda k: sum(1 for r in rows if k in r["src"])
    print(f"{p:10} distinct={tot:3} osv={s('osv'):3} audit={s('audit'):3} phpwarden={s('pw'):3} pw-missed={sum(1 for r in rows if 'pw' not in r['src']):3} pw-only={sum(1 for r in rows if r['src']==['pw']):3}")
json.dump(out,open("results.json","w"),default=list,indent=1)
