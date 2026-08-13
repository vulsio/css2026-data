#!/usr/bin/env python3
"""C4 for Cisco: delay from Cisco advisory publication to CPE assignment in NVD/VulnCheck."""
import os, sys
sys.argv = ["c4.py", "1", "none"]          # suppress c4.py's own report sections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c4                                   # noqa: E402
from c123b import BASE, load                # noqa: E402

CS = os.path.join(BASE, "vuls-data-raw-cisco-json")
pub = {}
for root, _, files in os.walk(CS):
    for fn in files:
        if not fn.endswith(".json"):
            continue
        d = load(os.path.join(root, fn))
        if not d:
            continue
        p = (d.get("firstPublished") or "")[:10]
        for c in d.get("cves") or []:
            if c and c.startswith("CVE-") and p and (c not in pub or p < pub[c]):
                pub[c] = p

print("### C4（Cisco）: Ciscoアドバイザリ公開日を起点とした付与遅延")
for name in ("NVD", "VulnCheck"):
    d, cen, seen = c4.measure(name, pub, every=1)
    print(f"{name:<10}: {c4.stats(d)}")
    print(f"{'':<10}  観測 {seen}件中 付与済み {len(d)}件 / 打切り {cen}件")
