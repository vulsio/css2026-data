#!/usr/bin/env python3
"""C4 for Fortinet using CVRF/CSAF initial_release_date as t0."""
import os, sys
sys.argv = ["c4.py", "1", "none"]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c4                      # noqa: E402
import fortinet_c123 as F      # noqa: E402

_, cdates, _, _, _ = F.load_cvrf()
_, _, sdates, _, _ = F.load_csaf()
pub = dict(cdates)
for c, d in sdates.items():                    # CSAF wins when earlier
    if c not in pub or d < pub[c]:
        pub[c] = d
print(f"### C4（Fortinet, CVRF/CSAF基準）: 起点となる公開日を持つCVE {len(pub)}件")
for name in ("NVD", "VulnCheck"):
    d, cen, seen = c4.measure(name, pub, every=1)
    print(f"{name:<10}: {c4.stats(d)}")
    print(f"{'':<10}  観測 {seen}件中 付与済み {len(d)}件 / 打切り {cen}件")
