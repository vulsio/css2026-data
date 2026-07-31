#!/usr/bin/env python3
"""C1 and C4 for Cisco Security Advisories (no product->CPE mapping required)."""
import json, os, re, sys, datetime as dt
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c123b import BASE, NVD, VC, load  # noqa

CS = os.path.join(BASE, "vuls-data-raw-cisco-json")
adv, nocve, cves = 0, [], {}
prodver = Counter()
for root, _, files in os.walk(CS):
    for fn in files:
        if not fn.endswith(".json"):
            continue
        d = load(os.path.join(root, fn))
        if not d:
            continue
        adv += 1
        pub = (d.get("firstPublished") or "")[:10]
        cs = [c for c in (d.get("cves") or []) if c and c.startswith("CVE-")]
        if not cs:
            nocve.append((d.get("advisoryId"), pub))
        for c in cs:
            if c not in cves or (pub and pub < cves[c]):
                cves[c] = pub
        # how many productNames carry a parseable trailing version?
        for p in d.get("productNames") or []:
            prodver["版あり" if re.search(r"\s\d[\d.\w()-]*$", p.strip()) else "版なし"] += 1

print(f"### Cisco一次データソース: アドバイザリ {adv}件 / CVE {len(cves)}件")
print(f"### C1a（CVE未採番のアドバイザリ）: {len(nocve)}件  例 {nocve[:4]}")
miss_n = [c for c in cves if not os.path.exists(os.path.join(NVD, c.split('-')[1], c + '.json'))]
miss_v = [c for c in cves if not os.path.exists(os.path.join(VC, c.split('-')[1], c + '.json'))]
print(f"### C1b（未収録）: NVD {len(miss_n)}件, VulnCheck {len(miss_v)}件  例 {sorted(miss_n)[:5]}")
t = sum(prodver.values()) or 1
print(f"### productNames {t}件中 " + ", ".join(f"{k}={v}({100*v/t:.1f}%)" for k, v in prodver.most_common()))
print(f"###   → CPEが無いため C2/C3 には製品名→CPEの対応付けが必要")
