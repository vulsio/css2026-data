#!/usr/bin/env python3
"""Final aggregation: Rejected records excluded throughout (they carry no product data by design)."""
import csv
import datetime as dt
from collections import Counter, defaultdict

OUT = "/tmp/claude-1000/-home-mainek00n-github-github-com-vulsio-css2026-data/37e4581d-b165-4be5-a3b7-036152d3298a/scratchpad"
SNAP = dt.date(2026, 7, 29)

nvd = {}
with open(f"{OUT}/nvd.csv") as f:
    for r in csv.DictReader(f):
        nvd[r["id"]] = r
vc = {}
with open(f"{OUT}/vc.csv") as f:
    for r in csv.DictReader(f):
        vc[r["id"]] = r

live = {k: v for k, v in nvd.items() if v["vulnStatus"] != "Rejected"}
print(f"### entries: all={len(nvd)} non-rejected={len(live)} rejected={len(nvd)-len(live)}")
print()

by_year = defaultdict(list)
for r in live.values():
    by_year[r["published"][:4]].append(r)

print("### Table: per publication year (Rejected excluded)")
print("year\tCVEs\tAnalyzed+Mod%\tAwait+Recv%\tDeferred%\tnvdCPE%\tvcAnyCPE%\tfillN\tfill%\tcnaAff%")
for y in sorted(by_year):
    if y < "2016":
        continue
    rs = by_year[y]
    n = len(rs)
    c = Counter(r["vulnStatus"] for r in rs)
    nvd_cpe = sum(1 for r in rs if int(r["vulnerable"]) > 0)
    vc_any = fill = 0
    for r in rs:
        v = vc.get(r["id"])
        if not v:
            continue
        a, b = int(v["nvdVuln"]) > 0, int(v["vcVuln"]) > 0
        if a or b:
            vc_any += 1
        if not a and b:
            fill += 1
    aff = sum(1 for r in rs if int(r["affSrc"]) > 0)
    print(f"{y}\t{n}\t{100*(c['Analyzed']+c['Modified'])/n:.1f}\t"
          f"{100*(c['Awaiting Analysis']+c['Received']+c['Undergoing Analysis'])/n:.1f}\t"
          f"{100*c['Deferred']/n:.1f}\t{100*nvd_cpe/n:.1f}\t{100*vc_any/n:.1f}\t"
          f"{fill}\t{100*fill/n:.1f}\t{100*aff/n:.1f}")
print()

print("### CVE publication volume (all statuses, incl. Rejected) and non-rejected")
for y in [str(x) for x in range(2016, 2027)]:
    allc = sum(1 for r in nvd.values() if r["published"][:4] == y)
    print(f"{y}\tall={allc}\tnonRejected={len(by_year.get(y,[]))}")
print("  2026 is partial: 2026-01-01..2026-07-29 (210 days)")
print()

print("### NVD enrichment latency proxy: lastModified - published for status=='Analyzed'")
print("(caveat: entries later revised become 'Modified' and drop out of this sample)")
print("pubYear\tn\tmedian\tp75\tp90\t>30d%\t>90d%")
for y in [str(x) for x in range(2020, 2027)]:
    ds = []
    for r in live.values():
        if r["vulnStatus"] != "Analyzed" or r["published"][:4] != y:
            continue
        try:
            ds.append((dt.date.fromisoformat(r["lastModified"]) - dt.date.fromisoformat(r["published"])).days)
        except ValueError:
            pass
    if not ds:
        continue
    ds.sort()
    q = lambda p: ds[min(len(ds) - 1, int(len(ds) * p))]
    print(f"{y}\t{len(ds)}\t{q(.5)}\t{q(.75)}\t{q(.9)}\t"
          f"{100*sum(1 for d in ds if d>30)/len(ds):.1f}\t{100*sum(1 for d in ds if d>90)/len(ds):.1f}")
print()

print("### age of entries still unenriched, by status (snapshot 2026-07-29)")
for st in ["Received", "Awaiting Analysis", "Undergoing Analysis", "Deferred"]:
    ds = []
    for r in live.values():
        if r["vulnStatus"] != st:
            continue
        try:
            ds.append((SNAP - dt.date.fromisoformat(r["published"])).days)
        except ValueError:
            pass
    if not ds:
        continue
    ds.sort()
    q = lambda p: ds[min(len(ds) - 1, int(len(ds) * p))]
    print(f"{st}\tn={len(ds)}\tmedian={q(.5)}\tp75={q(.75)}\tp90={q(.9)}\tmax={ds[-1]}\t>90d={sum(1 for d in ds if d>90)}")
print()

print("### per-CNA (Rejected excluded, published>=2024)")
print("CNA\tCVEs\tnvdCPE%\tvcAny%\tfill%\tcnaAff%\tDeferred%\tAwait%")
CNA = {"psirt@fortinet.com": "Fortinet", "psirt@cisco.com": "Cisco",
       "secure@microsoft.com": "Microsoft", "product-security@apple.com": "Apple",
       "security@apache.org": "Apache", "openssl-security@openssl.org": "OpenSSL",
       "vultures@jpcert.or.jp": "JPCERT/CC",
       "security-advisories@github.com": "GitHub", "audit@patchstack.com": "Patchstack",
       "cna@vuldb.com": "VulDB", "cve@mitre.org": "MITRE",
       "disclosure@vulncheck.com": "VulnCheck(CNA)"}
for sid, name in CNA.items():
    rs = [r for r in live.values() if r["source"] == sid and r["published"][:4] >= "2024"]
    if not rs:
        print(f"{name}\t0")
        continue
    n = len(rs)
    c = Counter(r["vulnStatus"] for r in rs)
    nvd_cpe = sum(1 for r in rs if int(r["vulnerable"]) > 0)
    vc_any = fill = 0
    for r in rs:
        v = vc.get(r["id"])
        if not v:
            continue
        a, b = int(v["nvdVuln"]) > 0, int(v["vcVuln"]) > 0
        if a or b:
            vc_any += 1
        if not a and b:
            fill += 1
    aff = sum(1 for r in rs if int(r["affSrc"]) > 0)
    print(f"{name}\t{n}\t{100*nvd_cpe/n:.1f}\t{100*vc_any/n:.1f}\t{100*fill/n:.1f}\t"
          f"{100*aff/n:.1f}\t{100*c['Deferred']/n:.1f}\t"
          f"{100*(c['Awaiting Analysis']+c['Received']+c['Undergoing Analysis'])/n:.1f}")
print()

print("### where NVD has no CPE (published>=2024, Rejected excluded): fallback availability")
rs = [r for r in live.values() if r["published"][:4] >= "2024" and int(r["vulnerable"]) == 0]
n = len(rs)
aff = sum(1 for r in rs if int(r["affSrc"]) > 0)
vcfill = sum(1 for r in rs if vc.get(r["id"]) and int(vc[r["id"]]["vcVuln"]) > 0)
neither = sum(1 for r in rs
              if int(r["affSrc"]) == 0 and not (vc.get(r["id"]) and int(vc[r["id"]]["vcVuln"]) > 0))
print(f"n={n}  CNA-affected present={aff} ({100*aff/n:.1f}%)  "
      f"vcConfigurations present={vcfill} ({100*vcfill/n:.1f}%)  "
      f"neither={neither} ({100*neither/n:.1f}%)")
