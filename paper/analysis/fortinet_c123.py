#!/usr/bin/env python3
"""C1-C3 for Fortinet using the authoritative CVRF / CSAF feeds.

The HTML-derived vuls-data-raw-fortinet must not be used: it does not keep up with
Fortinet's CVRF/CSAF updates. CVRF enumerates affected versions exactly but carries no
fixed versions, so it yields C2 and C3a (missed detection) only. CSAF additionally
carries known_not_affected (the fixed versions), so it yields C3b (over-detection) too.
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c123b import BASE, NVD, VC, Cond, cpe_pp, load, nvd_conds, pv  # noqa: E402

CVRF = os.path.join(BASE, "vuls-data-raw-fortinet-cvrf")
CSAF = os.path.join(BASE, "vuls-data-raw-fortinet-csaf")


def pkey(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def split_pid(pid):
    """'FortiOS >=7.6.0|<=7.6.1' -> ('FortiOS', '>=7.6.0|<=7.6.1')"""
    m = re.match(r"^(?P<prod>[A-Za-z][\w .()\-]*?)\s*[/\-\s]\s*(?P<rest>[<>=\d].*)$", pid or "")
    return (m.group("prod").strip(), m.group("rest").strip()) if m else (None, None)


def points_from_rest(rest):
    """Representative boundary versions denoted by a version expression."""
    if rest is None:
        return []
    if "all versions" in rest:
        m = re.match(r"^(\d[\d.]*)", rest)
        return [pv(m.group(1) + ".0")] if m else []
    if re.search(r"[<>]=?", rest):
        out = []
        for part in rest.split("|"):
            m = re.match(r"\s*([<>]=?)\s*([\d][\d.\w]*)", part)
            if m:
                out.append(pv(m.group(2)))
        return [x for x in out if x]
    v = pv(rest)
    return [v] if v else []


# ---------------- CVRF: exact enumerated affected versions ----------------
def load_cvrf():
    """cve -> {product_key: {'P': set(versions)}}, plus advisory dates and C1a count."""
    aff = defaultdict(lambda: defaultdict(set))
    dates, nocve, nadv, ntree = {}, [], 0, 0
    for root, _, files in os.walk(CVRF):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            d = load(os.path.join(root, fn))
            if not d:
                continue
            nadv += 1
            tr = (d.get("documenttracking") or {})
            aid = ((tr.get("identification") or {}).get("id")) or fn[:-5]
            date = (tr.get("initial_release_date") or "")[:10]
            # product_id -> (product name, version)
            pmap = {}
            pt = d.get("product_tree") or {}
            if pt:
                ntree += 1

            def walk(b, prod=None):
                if b.get("type") == "Product Name":
                    prod = b.get("name")
                fpn = b.get("full_product_name")
                if fpn:
                    pid = fpn.get("product_id")
                    ver = b.get("name")
                    if pid:
                        pmap[pid] = (prod, ver)
                nb = b.get("branch")
                for c in (nb if isinstance(nb, list) else ([nb] if nb else [])):
                    walk(c, prod)
            br = pt.get("branch")
            for b in (br if isinstance(br, list) else ([br] if br else [])):
                walk(b)

            v = d.get("vulnerability") or {}
            cs = v.get("cve") or []
            cs = [c for c in (cs if isinstance(cs, list) else [cs]) if c]
            if not cs:
                nocve.append((aid, date))
                continue
            ps = v.get("product_statuses") or {}
            sts = ps.get("status")
            sts = sts if isinstance(sts, list) else ([sts] if sts else [])
            for st in sts:
                if (st or {}).get("type") != "Known Affected":
                    continue
                for pid in st.get("product_id") or []:
                    prod, ver = pmap.get(pid, (None, None))
                    if prod is None:
                        prod, rest = split_pid(pid)
                        ver = rest
                    vv = pv(ver) if ver else None
                    if prod and vv:
                        for c in cs:
                            aff[c][pkey(prod)].add(vv)
            for c in cs:
                if date and (c not in dates or date < dates[c]):
                    dates[c] = date
    return aff, dates, nocve, nadv, ntree


# ---------------- CSAF: affected ranges + fixed versions ----------------
def load_csaf():
    aff = defaultdict(lambda: defaultdict(set))
    naf = defaultdict(lambda: defaultdict(set))
    dates, nocve, nadv = {}, [], 0
    for root, _, files in os.walk(CSAF):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            d = load(os.path.join(root, fn))
            if not d:
                continue
            nadv += 1
            tr = ((d.get("document") or {}).get("tracking") or {})
            aid = tr.get("id") or fn[:-5]
            date = (tr.get("initial_release_date") or "")[:10]
            for x in d.get("vulnerabilities") or []:
                cve = x.get("cve")
                if not cve:
                    nocve.append((aid, date))
                    continue
                ps = x.get("product_status") or {}
                for pid in ps.get("known_affected") or []:
                    prod, rest = split_pid(pid)
                    if prod:
                        aff[cve][pkey(prod)].update(points_from_rest(rest))
                for pid in ps.get("known_not_affected") or []:
                    prod, rest = split_pid(pid)
                    if prod:
                        naf[cve][pkey(prod)].update(points_from_rest(rest))
                if date and (cve not in dates or date < dates[cve]):
                    dates[cve] = date
    for m in (aff, naf):
        for c in m:
            for p in m[c]:
                m[c][p] = {v for v in m[c][p] if v}
    return aff, naf, dates, nocve, nadv


def nvd_side(cve):
    y = cve.split("-")[1]
    nv = load(os.path.join(NVD, y, cve + ".json"))
    src = (nv or {}).get("sourceIdentifier") or ""
    vcd = load(os.path.join(VC, y, cve + ".json"))
    def keyed(conds):
        out = {}
        for pp, c in conds.items():
            k = pkey(pp.split(":")[1] if ":" in pp else pp)
            if k in out:
                out[k].rs.extend(c.rs)
                out[k].pts |= c.pts
            else:
                d2 = Cond(); d2.rs = list(c.rs); d2.pts = set(c.pts); out[k] = d2
        return out
    return (nv, vcd,
            keyed(nvd_conds(nv.get("configurations")) if nv else {}),
            keyed(nvd_conds((vcd.get("configurations") or []) +
                            (vcd.get("vcConfigurations") or [])) if vcd else {}),
            src)


def evaluate(aff, naf, label, buckets, dates, split_by_cna=False):
    res = {b: {k: Counter() for k in ("nvd", "vc")} for b in buckets}
    pts = {b: {k: Counter() for k in ("nvd", "vc")} for b in buckets}
    cves = {b: set() for b in buckets}
    c2sub = {b: Counter() for b in buckets}
    c1b = Counter()
    for cve, prods in sorted(aff.items()):
        y = (dates.get(cve) or "0000")[:4]
        bk = next((b for b in buckets if buckets[b][0] <= y < buckets[b][1]), None)
        if bk is None:
            continue
        nv, vcd, tn, tv, src = nvd_side(cve)
        if split_by_cna:
            bk = "Fortinet採番" if src == "psirt@fortinet.com" else "他者採番"
        if nv is None:
            c1b["nvd"] += 1
        if vcd is None:
            c1b["vc"] += 1
        cves[bk].add(cve)
        for pk, P in prods.items():
            if not P:
                continue
            N = (naf.get(cve) or {}).get(pk, set()) - P
            for key, tgt in (("nvd", tn), ("vc", tv)):
                tc = tgt.get(pk)
                if not tc:
                    res[bk][key]["C2"] += 1
                    if key == "nvd":
                        anyft = any(k.startswith("forti") for k in tgt)
                        c2sub[bk]["C2a 条件なし" if not tgt else
                                  ("C2b Fortinet製品が皆無" if not anyft else
                                   "C2c 別製品のみ")] += 1
                    pts[bk][key]["FN"] += len(P)
                    pts[bk][key]["N"] += len(P) + len(N)
                    continue
                fn = sum(1 for v in P if not tc.match(v))
                fp = sum(1 for v in N if tc.match(v))
                pts[bk][key]["FN"] += fn
                pts[bk][key]["FP"] += fp
                pts[bk][key]["N"] += len(P) + len(N)
                res[bk][key]["一致" if not fn and not fp else
                             ("双方" if fn and fp else ("C3a" if fn else "C3b"))] += 1
    V = ("一致", "C2", "C3a", "C3b", "双方")
    C2V = ("C2a 条件なし", "C2b Fortinet製品が皆無", "C2c 別製品のみ")
    print(f"### {label}")
    print(f"{'期間':<10}{'CVE':>5}{'組':>6}" + "".join(f" |{l:^47}" for l in ("NVD", "VulnCheck")))
    print(f"{'':<21}" + (" |" + "".join(f"{v:>7}" for v in V) +
                         f"{'未検知率':>7}{'過剰検知率':>8}") * 2)
    tot = {k: Counter() for k in ("nvd", "vc")}
    tpt = {k: Counter() for k in ("nvd", "vc")}
    for bk in buckets:
        n = sum(res[bk]["nvd"].values())
        if not n:
            continue
        row = f"{bk:<10}{len(cves[bk]):>5}{n:>6}"
        for k in ("nvd", "vc"):
            t = sum(res[bk][k].values()) or 1
            tot[k] += res[bk][k]; tpt[k] += pts[bk][k]
            row += " |" + "".join(f"{100*res[bk][k][v]/t:>7.1f}" for v in V)
            row += f"{100*pts[bk][k]['FN']/max(pts[bk][k]['N'],1):>6.1f}%"
            row += f"{100*pts[bk][k]['FP']/max(pts[bk][k]['N'],1):>7.1f}%"
        print(row)
    row = f"{'合計':<10}{sum(len(v) for v in cves.values()):>5}{sum(tot['nvd'].values()):>6}"
    for k in ("nvd", "vc"):
        t = sum(tot[k].values()) or 1
        row += " |" + "".join(f"{100*tot[k][v]/t:>7.1f}" for v in V)
        row += f"{100*tpt[k]['FN']/max(tpt[k]['N'],1):>6.1f}%"
        row += f"{100*tpt[k]['FP']/max(tpt[k]['N'],1):>7.1f}%"
    print(row)
    print(f"    C1b（NVD未収録）: {c1b['nvd']}件, （VulnCheck未収録）: {c1b['vc']}件")
    for bk in buckets:
        if sum(res[bk]["nvd"].values()):
            tt = sum(c2sub[bk].values()) or 1
            print(f"    C2内訳[{bk}] NVD: " + ", ".join(
                f"{k}={c2sub[bk][k]}({100*c2sub[bk][k]/tt:.0f}%)" for k in C2V))
    print(f"    検証点: " + ", ".join(
        f"{k}={tpt[k]['N']}点(未検知{tpt[k]['FN']}, 過剰検知{tpt[k]['FP']})" for k in ("nvd", "vc")))
    print()


if __name__ == "__main__":
    B = {"2022-2023": ("2022", "2024"), "2024": ("2024", "2025"),
         "2025": ("2025", "2026"), "2026": ("2026", "9999")}
    caff, cdates, cnocve, cnadv, cntree = load_cvrf()
    print(f"### CVRF: アドバイザリ {cnadv}件（うち製品情報あり {cntree}件），"
          f"CVE {len(cdates)}件，CVE未採番 {len(cnocve)}件")
    print(f"###   C1a 例: {cnocve[:4]}")
    print()
    evaluate(caff, {}, "CVRF基準（影響版を個別列挙。修正版を持たないため過剰検知は測定不可）",
             B, cdates)

    evaluate(caff, {}, "CVRF基準・採番元別", {"Fortinet採番": ("0000", "9999"),
                                            "他者採番": ("0000", "9999")}, cdates,
             split_by_cna=True)

    saff, snaf, sdates, snocve, snadv = load_csaf()
    print(f"### CSAF: アドバイザリ {snadv}件，CVE {len(sdates)}件，CVE未採番の脆弱性エントリ {len(snocve)}件")
    print()
    evaluate(saff, snaf, "CSAF基準（known_affected を正例，known_not_affected を負例）",
             B, sdates)
    evaluate(saff, snaf, "CSAF基準・採番元別", {"Fortinet採番": ("0000", "9999"),
                                          "他者採番": ("0000", "9999")}, sdates,
             split_by_cna=True)
