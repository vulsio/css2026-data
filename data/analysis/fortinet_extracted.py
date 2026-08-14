#!/usr/bin/env python3
"""C2/C3 for Fortinet using the *extracted* CVRF, i.e. with the P1 supplement applied.

fortinet_c123.py reads the raw CVRF, so it can only cover the advisories Fortinet
itself filled in (2022 onwards). The extracted artifact additionally carries the
supplement table generated in the P1 pattern, which restores detection conditions
for the 2012-2021 advisories whose product_statuses are empty upstream.

Positive/negative points come from the range bounds: an inclusive bound (ge/le) is a
version that must be detected, an exclusive bound (lt/gt) is one that must not be --
`lt: 4.3.8` says 4.3.8 is already fixed. Exact versions (eq) are positive points.

Note this scores NVD against a baseline we produced ourselves for the pre-2022 part.
The supplement is Fortinet-authored in origin (its handmade dataset and its CNA
records) but it is our transcription of it, so the two halves are reported separately.
"""
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c123b import BASE, load, pv  # noqa: E402
from fortinet_c123 import CVRF, evaluate, pkey  # noqa: E402

EXT = os.path.join(BASE, "vuls-data-extracted-fortinet-cvrf", "data")


def version_universe():
    """product_key -> {versions}: every version Fortinet ever enumerated in a CVRF
    product_tree. A range like `lt: 4.4.4` names only the fix, so the versions it
    covers have to come from somewhere; this is the closest thing to a release list
    the feed offers."""
    uni = {}
    for root, _, files in os.walk(CVRF):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            d = load(os.path.join(root, fn))
            if not d:
                continue

            def walk(b, prod=None):
                if b.get("type") == "Product Name":
                    prod = b.get("name")
                if b.get("type") == "Product Version" and prod and b.get("name"):
                    v = pv(b["name"])
                    if v:
                        uni.setdefault(pkey(prod), set()).add(v)
                nb = b.get("branch")
                for c in (nb if isinstance(nb, list) else ([nb] if nb else [])):
                    walk(c, prod)
            br = ((d.get("product_tree") or {}).get("branch"))
            for b in (br if isinstance(br, list) else ([br] if br else [])):
                walk(b)
    return uni


def in_range(v, r):
    for k, ok in (("ge", lambda a, b: a >= b), ("gt", lambda a, b: a > b),
                  ("le", lambda a, b: a <= b), ("lt", lambda a, b: a < b)):
        b = pv(r[k]) if r.get(k) else None
        if b and not ok(v, b):
            return False
    return True


UNI = {}


def load_extracted():
    """cve -> {product_key: {points}} for positives and negatives, plus dates."""
    aff = defaultdict(lambda: defaultdict(set))
    naf = defaultdict(lambda: defaultdict(set))
    dates, nadv, ncond = {}, 0, 0
    for root, _, files in os.walk(EXT):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            d = load(os.path.join(root, fn))
            if not d:
                continue
            nadv += 1
            cves = [(v.get("content") or {}).get("id") for v in d.get("vulnerabilities") or []]
            cves = [c for c in cves if c and c.startswith("CVE-")]
            date = ""
            for a in d.get("advisories") or []:
                date = ((a.get("content") or {}).get("published") or "")[:10] or date
            dets = d.get("detections") or []
            if not (cves and dets):
                continue
            ncond += 1
            for det in dets:
                for cond in det.get("conditions") or []:
                    for cr in ((cond.get("criteria") or {}).get("criterions") or []):
                        c = cr.get("cpe") or {}
                        if not c.get("vulnerable"):
                            continue
                        parts = (c.get("cpe") or "").split(":")
                        if len(parts) < 6:
                            continue
                        pk = pkey(parts[4])
                        # 2022 onwards the extractor keeps Fortinet's exact
                        # enumeration in cpe_matches; the supplemented years carry
                        # a range instead
                        for cm in c.get("cpe_matches") or []:
                            q = cm.split(":")
                            if len(q) > 5 and q[5] not in ("*", "-"):
                                v = pv(q[5])
                                if v:
                                    for cve in cves:
                                        aff[cve][pk].add(v)
                        r = c.get("range") or {}
                        pos = {pv(r[k]) for k in ("ge", "le", "eq") if r.get(k)}
                        neg = {pv(r[k]) for k in ("lt", "gt") if r.get(k)}
                        if not r and parts[5] not in ("*", "-"):
                            pos.add(pv(parts[5]))
                        # an lt/gt-only range names no version it covers; take the
                        # released versions that satisfy it from the universe
                        if r:
                            sat = sorted(v for v in UNI.get(pk, ()) if in_range(v, r))
                            if sat:
                                pos |= {sat[0], sat[-1]}
                        for cve in cves:
                            aff[cve][pk] |= {v for v in pos if v}
                            naf[cve][pk] |= {v for v in neg if v}
            for cve in cves:
                if date and (cve not in dates or date < dates[cve]):
                    dates[cve] = date
    return aff, naf, dates, nadv, ncond


if __name__ == "__main__":
    globals()["UNI"] = version_universe()
    print(f"### 版ユニバース: {len(UNI)}製品, {sum(len(v) for v in UNI.values())}版")
    aff, naf, dates, nadv, ncond = load_extracted()
    npos = sum(len(v) for p in aff.values() for v in p.values())
    nneg = sum(len(v) for p in naf.values() for v in p.values())
    print(f"### extracted CVRF: アドバイザリ {nadv}件（検知条件あり {ncond}件），"
          f"CVE {len(dates)}件，正例 {npos}点，負例 {nneg}点")
    print()
    B = {"〜2021（P1で補完）": ("0000", "2022"), "2022-2023": ("2022", "2024"),
         "2024": ("2024", "2025"), "2025-2026": ("2025", "9999")}
    evaluate(aff, naf, "extracted CVRF基準（P1の補完表を含む）", B, dates)
    evaluate(aff, naf, "extracted CVRF基準・採番元別",
             {"Fortinet採番": ("0000", "9999"), "他者採番": ("0000", "9999")},
             dates, split_by_cna=True)
