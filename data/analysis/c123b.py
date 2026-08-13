#!/usr/bin/env python3
"""C1-C3 via the boundary-value method of Sec.7: evaluate each condition on a
discrete set of test versions, so that "<= 6.4.15" and "< 6.4.16" are treated
as identical (they denote the same set of released versions)."""
import json
import os
import pathlib
import re
from collections import Counter, defaultdict

SP = "/tmp/claude-1000/-home-mainek00n-github-github-com-vulsio-css2026-data/37e4581d-b165-4be5-a3b7-036152d3298a/scratchpad"
FT = os.environ.get("FT_DIR", os.path.join(SP, "vuls-data-raw-fortinet"))
BASE = str(pathlib.Path(__file__).resolve().parents[2]
           / "ghcr.io/vulsio/vuls-data-db")
NVD = os.path.join(BASE, "vuls-data-raw-nvd-feed-cve-v2")
VC = os.path.join(BASE, "vuls-data-raw-vulncheck-nist-nvd2")
PAD = 6


def pv(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s or s in ("*", "-"):
        return None
    out = []
    for p in re.split(r"[.\-_]", s):
        m = re.match(r"^(\d+)", p)
        if not m:
            if out:
                break
            return None
        out.append(int(m.group(1)))
    return tuple((out + [0] * PAD)[:PAD]) if out else None


def cpe_pp(c):
    p = c.split(":")
    return f"{p[3]}:{p[4]}" if len(p) > 5 else None


def load(p):
    try:
        with open(p, "rb") as f:
            return json.load(f)
    except Exception:
        return None


class Cond:
    """A version condition: list of (lo, lo_closed, hi, hi_closed); None = unbounded."""

    def __init__(self):
        self.rs = []
        self.pts = set()      # endpoint versions mentioned (for the test universe)

    def add(self, lo, lo_cl, hi, hi_cl):
        self.rs.append((lo, lo_cl, hi, hi_cl))
        for v in (lo, hi):
            if v:
                self.pts.add(v)

    def match(self, v):
        for lo, lo_cl, hi, hi_cl in self.rs:
            ok = True
            if lo is not None:
                ok = (v >= lo) if lo_cl else (v > lo)
            if ok and hi is not None:
                ok = (v <= hi) if hi_cl else (v < hi)
            if ok:
                return True
        return False

    def __bool__(self):
        return bool(self.rs)


def ft_cond(aff, cond):
    eq = str(aff.get("eq", "")).strip()
    if eq.upper() == "ANY":
        cond.add(None, True, None, True)   # vendor states every version is affected
        return
    if eq.upper() == "NA":
        return                             # hardware entry: version not applicable
    if eq:
        v = pv(eq)
        if v:
            cond.add(v, True, v, True)
        return
    if "eq" in aff and not any(str(aff.get(k, "")).strip() for k in ("ge", "gt", "le", "lt")):
        return                             # extractor produced no version at all
    lo = lo_cl = hi = hi_cl = None
    if "ge" in aff:
        lo, lo_cl = pv(aff["ge"]), True
    elif "gt" in aff:
        lo, lo_cl = pv(aff["gt"]), False
    if "le" in aff:
        hi, hi_cl = pv(aff["le"]), True
    elif "lt" in aff:
        hi, hi_cl = pv(aff["lt"]), False
    if lo is not None or hi is not None:
        cond.add(lo, bool(lo_cl), hi, bool(hi_cl))


def nvd_conds(cfgs):
    d = defaultdict(Cond)
    for cfg in cfgs or []:
        for n in cfg.get("nodes") or []:
            for m in n.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                cri = m.get("criteria", "")
                pp = cpe_pp(cri)
                if not pp:
                    continue
                lo = lo_cl = hi = hi_cl = None
                if "versionStartIncluding" in m:
                    lo, lo_cl = pv(m["versionStartIncluding"]), True
                elif "versionStartExcluding" in m:
                    lo, lo_cl = pv(m["versionStartExcluding"]), False
                if "versionEndIncluding" in m:
                    hi, hi_cl = pv(m["versionEndIncluding"]), True
                elif "versionEndExcluding" in m:
                    hi, hi_cl = pv(m["versionEndExcluding"]), False
                if lo is None and hi is None:
                    parts = cri.split(":")
                    ver = pv(parts[5]) if len(parts) > 5 else None
                    if ver:
                        d[pp].add(ver, True, ver, True)
                    else:
                        d[pp].add(None, True, None, True)   # all versions
                else:
                    d[pp].add(lo, bool(lo_cl), hi, bool(hi_cl))
    return d


if __name__ == "__main__":
    # ---------- Fortinet primary source ----------
    ft = {}
    noc = []
    for root, _, files in os.walk(FT):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            d = load(os.path.join(root, fn))
            if not d:
                continue
            pub = (d.get("published") or "")[:10]
            for v in d.get("vulnerabilities") or []:
                cve = v.get("cve")
                if not cve:
                    noc.append((d["id"], pub))
                    continue
                e = ft.setdefault(cve, {"c": defaultdict(Cond), "fixed": defaultdict(set),
                                        "adv": set(), "pub": pub})
                e["adv"].add(d["id"])
                if pub and (not e["pub"] or pub < e["pub"]):
                    e["pub"] = pub
                for de in v.get("definitions") or []:
                    for c in de.get("configurations") or []:
                        for n in c.get("nodes") or []:
                            pp = cpe_pp(n.get("cpe", ""))
                            if not pp:
                                continue
                            ft_cond(n.get("affected") or {}, e["c"][pp])
                            for fx in n.get("fixed_in") or []:
                                fv = pv(fx)
                                if fv:
                                    e["fixed"][pp].add(fv)

    print(f"### Fortinet 一次データソース: アドバイザリ1,114件 / CVE {len(ft)}件 / "
          f"CVE未採番の脆弱性エントリ {len(noc)}件")
    print(f"### C1a（未採番による欠落）: {len(noc)}件．例 {noc[:4]}")
    print()


    def report(scope, cves):
        if not cves:
            return
        c1b = Counter()
        verdict = {"nvd": Counter(), "vc": Counter()}
        pts = {"nvd": Counter(), "vc": Counter()}
        npair = 0
        for cve in cves:
            e = ft[cve]
            y = cve.split("-")[1]
            nv = load(os.path.join(NVD, y, cve + ".json"))
            vcd = load(os.path.join(VC, y, cve + ".json"))
            if nv is None:
                c1b["nvd"] += 1
            if vcd is None:
                c1b["vc"] += 1
            tgt = {
                "nvd": nvd_conds(nv.get("configurations")) if nv else {},
                "vc": nvd_conds((vcd.get("configurations") or []) +
                                (vcd.get("vcConfigurations") or [])) if vcd else {},
            }
            for pp, fc in e["c"].items():
                if not fc:
                    continue
                npair += 1
                universe = set(fc.pts) | e["fixed"].get(pp, set())
                for key in ("nvd", "vc"):
                    tc = tgt[key].get(pp)
                    if tc:
                        universe |= tc.pts
                for key in ("nvd", "vc"):
                    tc = tgt[key].get(pp)
                    if not tc:
                        verdict[key]["C2 製品欠落"] += 1
                        pts[key]["FN"] += sum(1 for v in universe if fc.match(v))
                        continue
                    fn = fp = 0
                    for v in universe:
                        a, b = fc.match(v), tc.match(v)
                        if a and not b:
                            fn += 1
                        elif b and not a:
                            fp += 1
                    pts[key]["FN"] += fn
                    pts[key]["FP"] += fp
                    pts[key]["TOTAL"] += len(universe)
                    if not fn and not fp:
                        verdict[key]["一致"] += 1
                    elif fn and fp:
                        verdict[key]["C3 未検知と過剰検知の双方"] += 1
                    elif fn:
                        verdict[key]["C3a 未検知（NVD側が狭い）"] += 1
                    else:
                        verdict[key]["C3b 過剰検知（NVD側が広い）"] += 1

        print(f"--- {scope}: CVE {len(cves)}件 / 比較した(CVE,製品)組 {npair}組")
        print(f"    C1b（採番済みだが未収録）: NVD {c1b['nvd']}件, VulnCheck {c1b['vc']}件")
        for key, label in (("nvd", "NVD      "), ("vc", "VulnCheck")):
            t = sum(verdict[key].values()) or 1
            items = "  ".join(f"{k}={v}({100*v/t:.1f}%)" for k, v in
                              sorted(verdict[key].items(), key=lambda x: -x[1]))
            tp = pts[key]["TOTAL"] or 1
            print(f"    {label}: {items}")
            print(f"    {' '*len(label)}  検証点 {pts[key]['TOTAL']}点中 未検知 {pts[key]['FN']}点"
                  f"({100*pts[key]['FN']/tp:.1f}%) 過剰検知 {pts[key]['FP']}点({100*pts[key]['FP']/tp:.1f}%)")
        print()


    report("全期間", sorted(ft))
    report("Fortinet公開日が2024年以降", sorted(c for c in ft if ft[c]["pub"] >= "2024"))
    report("Fortinet公開日が2025年以降", sorted(c for c in ft if ft[c]["pub"] >= "2025"))
