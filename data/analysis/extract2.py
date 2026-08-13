#!/usr/bin/env python3
"""Granularity of detection conditions + per-vendor drill-down (published >= 2024)."""
import json
import os
import pathlib
from collections import Counter, defaultdict
from multiprocessing import Pool

BASE = str(pathlib.Path(__file__).resolve().parents[2]
           / "ghcr.io/vulsio/vuls-data-db")
NVD = os.path.join(BASE, "vuls-data-raw-nvd-feed-cve-v2")
VC = os.path.join(BASE, "vuls-data-raw-vulncheck-nist-nvd2")
DIRS = sorted(y for y in __import__("os").listdir(NVD) if y.isdigit())

VENDORS = {
    "psirt@fortinet.com": "Fortinet",
    "psirt@cisco.com": "Cisco",
    "secure@microsoft.com": "Microsoft",
    "product-security@apple.com": "Apple",
    "security@apache.org": "Apache",
    "openssl-security@openssl.org": "OpenSSL",
    "vultures@jpcert.or.jp": "JPCERT/CC",
}


def classify(m):
    """Granularity class of one cpeMatch."""
    if any(k in m for k in ("versionStartIncluding", "versionStartExcluding",
                            "versionEndIncluding", "versionEndExcluding")):
        return "range"
    parts = m.get("criteria", "").split(":")
    ver = parts[5] if len(parts) > 5 else "*"
    if ver == "*":
        return "any"      # matches every version of the product -> over-broad
    if ver == "-":
        return "na"       # version not applicable (firmware/hardware style)
    return "exact"


def gran(cfgs):
    c = Counter()
    for cfg in cfgs or []:
        for n in cfg.get("nodes") or []:
            for m in n.get("cpeMatch") or []:
                if m.get("vulnerable"):
                    c[classify(m)] += 1
    return c


def work(year):
    nvd_gran = Counter()
    vc_gran = Counter()
    nvd_entry = Counter()   # per-entry: best granularity available
    vc_entry = Counter()
    per_vendor = defaultdict(Counter)
    examples = defaultdict(list)
    d = os.path.join(NVD, year)
    for fn in os.listdir(d):
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(d, fn), "rb") as f:
            r = json.load(f)
        if (r.get("published") or "")[:4] < "2024":
            continue
        if (r.get("vulnStatus") or "") == "Rejected":   # withdrawn records carry no product data by design
            continue
        cid = r["id"]
        src = r.get("sourceIdentifier") or ""
        g = gran(r.get("configurations"))
        nvd_gran += g
        best = ("range" if g["range"] else "exact" if g["exact"]
                else "any" if g["any"] else "na" if g["na"] else "none")
        nvd_entry[best] += 1

        vp = os.path.join(VC, year, fn)
        gv = Counter()
        if os.path.exists(vp):
            with open(vp, "rb") as f:
                v = json.load(f)
            gv = gran(v.get("vcConfigurations"))
            vc_gran += gv
        combined = g + gv
        vbest = ("range" if combined["range"] else "exact" if combined["exact"]
                 else "any" if combined["any"] else "na" if combined["na"] else "none")
        vc_entry[vbest] += 1

        if src in VENDORS:
            name = VENDORS[src]
            per_vendor[name]["total"] += 1
            per_vendor[name]["st_" + (r.get("vulnStatus") or "?")] += 1
            per_vendor[name]["y_" + (r.get("published") or "")[:4]] += 1
            if sum(g.values()) == 0:
                per_vendor[name]["nvd_nocpe"] += 1
                if sum(gv.values()) == 0:
                    per_vendor[name]["both_nocpe"] += 1
                    if len(examples[name]) < 4:
                        examples[name].append((cid, r.get("published", "")[:10],
                                               r.get("vulnStatus"), len(r.get("affected") or [])))
            if g["range"] or g["exact"]:
                per_vendor[name]["nvd_versioned"] += 1
            if combined["range"] or combined["exact"]:
                per_vendor[name]["comb_versioned"] += 1
    return nvd_gran, vc_gran, nvd_entry, vc_entry, per_vendor, examples


if __name__ == "__main__":
    with Pool(16) as p:
        res = p.map(work, DIRS)
    NG, VG, NE, VE = Counter(), Counter(), Counter(), Counter()
    PV = defaultdict(Counter)
    EX = defaultdict(list)
    for ng, vg, ne, ve, pv, ex in res:
        NG += ng; VG += vg; NE += ne; VE += ve
        for k, v in pv.items():
            PV[k] += v
        for k, v in ex.items():
            EX[k].extend(v)

    def pct(c):
        t = sum(c.values()) or 1
        return {k: f"{v}({100*v/t:.1f}%)" for k, v in sorted(c.items(), key=lambda x: -x[1])}

    print("### cpeMatch granularity, vulnerable matches only, published>=2024")
    print("NVD configurations   :", sum(NG.values()), pct(NG))
    print("VulnCheck vcConfigs  :", sum(VG.values()), pct(VG))
    print()
    print("### per-entry best available granularity, published>=2024")
    print("NVD only             :", sum(NE.values()), pct(NE))
    print("NVD + vcConfigs      :", sum(VE.values()), pct(VE))
    print()
    print("### per-vendor drill-down (published>=2024)")
    for name, c in sorted(PV.items()):
        t = c["total"]
        print(f"-- {name}: total={t}")
        print(f"   by year: ", {k[2:]: v for k, v in sorted(c.items()) if k.startswith('y_')})
        print(f"   status : ", {k[3:]: v for k, v in sorted(c.items(), key=lambda x: -x[1]) if k.startswith('st_')})
        print(f"   NVD no-CPE={c['nvd_nocpe']} ({100*c['nvd_nocpe']/t:.1f}%)  "
              f"both no-CPE={c['both_nocpe']} ({100*c['both_nocpe']/t:.1f}%)")
        print(f"   version-identifiable: NVD={100*c['nvd_versioned']/t:.1f}%  "
              f"NVD+vc={100*c['comb_versioned']/t:.1f}%")
        if EX[name]:
            print(f"   examples w/o any CPE (id, published, status, #affectedSrc): {EX[name][:4]}")
