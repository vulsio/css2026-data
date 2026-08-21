#!/usr/bin/env python3
"""本文中の、他の *.out が扱っていない数値を再計算する。

3.3節のWindows、5.2節(2)(4)(6)、5.4節のApple欠落が対象。
それぞれ「論文のどこの数値か」と「どう数えたか」を添えて出力する。
3.5節の安定性は Git 履歴を辿るため stability.py に分けた。

    VULS_DATA_ROOT=data/db/ghcr.io/vulsio/vuls-data-db python3 data/analysis/paper_numbers.py
"""

import collections
import glob
import json
import os
import re
import sys
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect_eval as D  # noqa: E402  検知結果の読み込みと製品割り当てを共有する

DB = D.NVD_RAW.parent
VC_RAW = DB / "vuls-data-raw-vulncheck-nist-nvd2"
LOW = ("versionStartIncluding", "versionStartExcluding")
HIGH = ("versionEndIncluding", "versionEndExcluding")
MS_CNA = "secure@microsoft.com"
MACOS = ("macos", "mac_os_x")  # 5.1節のとおり mac_os_x は macos に寄せる


def cpe_of(m):
    """vulnerable な cpeMatch から (vendor, product, versionPart) を取り出す"""
    p = (m.get("criteria") or "").split(":")
    return (p[3], p[4], p[5]) if len(p) > 5 else None


def matches(doc, field, want):
    """doc[field] の vulnerable な cpeMatch のうち want(vendor, product) を満たすもの"""
    for cfg in doc.get(field) or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                c = cpe_of(m)
                if c and want(c[0], c[1]):
                    yield m, c[2]


def bounded(m, ver):
    """版が何らかの形で絞られているか（範囲指定があるか、版部が具体的か）"""
    return ver not in ("*", "-") or any(k in m for k in LOW + HIGH)


def no_lower_bound(m, ver):
    """下限を持たない＝版部がワイルドカードで versionStart* も無い"""
    return ver in ("*", "-") and not any(k in m for k in LOW)


def read(root, cve):
    try:
        return json.loads((root / str(D.year(cve)) / f"{cve}.json").read_text())
    except OSError:
        return None


# ---------------- NVD 全件走査（CPEの形） ----------------

def _scan_year(year):
    c = collections.Counter()
    d = os.path.join(str(D.NVD_RAW), year)
    for fn in os.listdir(d):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, fn), "rb") as f:
                r = json.load(f)
        except Exception:
            continue
        # 5.2(2) Apple: macos/mac_os_x の cpeMatch のうち下限を持たないもの
        for m, ver in matches(r, "configurations", lambda v, p: v == "apple" and p in MACOS):
            c["apple_all"] += 1
            if no_lower_bound(m, ver):
                c["apple_nolow"] += 1
        # 5.2(4) Cisco: cisco:ios の cpeMatch のうち範囲指定を伴うもの
        for m, ver in matches(r, "configurations", lambda v, p: (v, p) == ("cisco", "ios")):
            c["ios_all"] += 1
            if any(k in m for k in LOW + HIGH):
                c["ios_ranged"] += 1
        # 3.3 Windows: Microsoft採番・2024年以降のCVE単位
        if (r.get("sourceIdentifier") or "") == MS_CNA \
                and (r.get("published") or "")[:4] >= "2024" \
                and (r.get("vulnStatus") or "") != "Rejected":
            win = [(m, ver) for m, ver in
                   matches(r, "configurations",
                           lambda v, p: v == "microsoft" and p.startswith("windows"))]
            if win:
                c["win_cve"] += 1
                if any(any(k in m for k in LOW + HIGH) for m, _ in win):
                    c["win_cve_ranged"] += 1
    return c


def nvd_shapes():
    years = sorted(y for y in os.listdir(str(D.NVD_RAW)) if y.isdigit())
    tot = collections.Counter()
    with Pool(16) as p:
        for c in p.map(_scan_year, years):
            tot.update(c)
    return tot


# ---------------- 検知結果から ----------------

def detected(vendor, server):
    """{slot: {製品: CVE集合}}"""
    osp = D.os_product_of(vendor, server)
    return {slot: D.load(vendor, slot, server, osp)[0] for slot, _ in D.SLOTS}


def apple_cve_sets():
    """Apple Security Releases の (全CVE, macOSを対象とするアドバイザリのCVE)"""
    allc, mac = set(), set()
    for path in glob.glob(str(DB / "vuls-data-extracted-apple-security-releases" / "data" / "*.json")):
        d = json.load(open(path))
        ids = {i for v in d.get("vulnerabilities") or []
               if (i := (v.get("content") or {}).get("id"))}
        allc |= ids
        blob = json.dumps(d.get("detections") or [])
        if any(f"apple:{p}" in blob for p in MACOS):
            mac |= ids
    return allc, mac


def cisco_versionless():
    """検知条件が付いたCisco CVEのうち、版を持たない productName を含むアドバイザリのもの"""
    ver = re.compile(r"\s\d[\d.\w()-]*$")  # cisco_c14.py と同じ判定
    mapped_adv, mapped_cve = set(), set()
    for path in glob.glob(str(DB / "vuls-data-extracted-cisco-json" / "data" / "*" / "*.json")):
        d = json.load(open(path))
        if not (d.get("detections") or []):
            continue
        mapped_adv.add(d.get("id") or os.path.basename(path)[:-5])
        mapped_cve |= {i for v in d.get("vulnerabilities") or []
                       if (i := (v.get("content") or {}).get("id"))}
    nover = set()
    for path in glob.glob(str(DB / "vuls-data-raw-cisco-json" / "*" / "*.json")):
        d = json.load(open(path))
        if (d.get("advisoryId") or os.path.basename(path)[:-5]) not in mapped_adv:
            continue
        if any(not ver.search(n.strip()) for n in d.get("productNames") or []):
            nover |= set(d.get("cves") or [])
    return mapped_cve, nover & mapped_cve


def main():
    print("### 本文の数値の再計算（他の *.out が扱っていないもの）")

    n = nvd_shapes()
    print("\n[3.3] Microsoft採番・2024年以降でWindows製品のCPEを持つCVE")
    print(f"    {n['win_cve']}件中 {n['win_cve_ranged']}件"
          f"（{100 * n['win_cve_ranged'] / n['win_cve']:.1f}%）が範囲指定を伴うWindows CPEを持つ")

    print("\n[5.2(2)] AppleのCPE（apple:macos と apple:mac_os_x、vulnerable のみ）")
    print(f"    全 {n['apple_all']}件中 下限を持たないもの {n['apple_nolow']}件"
          f"（{100 * n['apple_nolow'] / n['apple_all']:.1f}%）")

    print("\n[5.2(4)] cisco:ios の cpeMatch（vulnerable のみ）")
    print(f"    全 {n['ios_all']}件中 範囲指定 {n['ios_ranged']}件")

    print("\n[5.2(2)] macOSへの過剰検知が下限なしCPEで説明できるか")
    for server, label in (("macos", "macOS 14.7.4"), ("macos_x", "macOS 10.13.3")):
        s = detected("apple", server)
        over = s["01"]["apple:macos"] - s["00"]["apple:macos"]
        hit = sum(1 for c in over
                  if (d := read(D.NVD_RAW, c))
                  and any(no_lower_bound(m, v) for m, v in
                          matches(d, "configurations", lambda ve, p: ve == "apple" and p in MACOS)))
        print(f"    {label}: DB-nvd 過剰検知 {len(over)}件 / 下限なしCPEを持つもの {hit}件"
              f"（{100 * hit / len(over):.1f}%）")

    s = detected("apple", "macos_x")
    prim, nvd, vc = (s[k]["apple:macos"] for k in ("00", "01", "02"))
    over_vc, only_vc = vc - prim, (vc - prim) - nvd
    loosened = sum(1 for c in only_vc
                   if (d := read(D.NVD_RAW, c))
                   and any(bounded(m, v) for m, v in
                           matches(d, "configurations", lambda ve, p: ve == "apple" and p in MACOS)))
    print(f"    macOS 10.13.3: DB-vc 過剰検知 {len(over_vc)}件 / DB-nvdが検知しない {len(only_vc)}件 /"
          f" うちNVDがmacOSに版を書いているもの {loosened}件")

    print("\n[5.2(4)] Ciscoが版を書いていない場合")
    mapped, nover = cisco_versionless()
    print(f"    検知条件が付いたCVE {len(mapped)}件中 {len(nover)}件"
          f"（{100 * len(nover) / len(mapped):.1f}%）が、版を持たない productName を含むアドバイザリのもの")

    print("\n[5.2(6)] OpenSSHでDB-nvdだけが検知したCVEの公開年")
    for server in ("openssh_8-5p1", "openssh_9-6p1"):
        t = detected("openssh", server)
        only = t["01"]["openbsd:openssh"] - t["00"]["openbsd:openssh"]
        years = collections.Counter(D.year(c) for c in only)
        print(f"    {server}: {len(only)}件 / 2026年公開 {years[2026]}件"
              f"（{100 * years[2026] / len(only):.0f}%）  年別={dict(sorted(years.items()))}")

    print("\n[5.4] macOS 10.13.3への過剰検知のうちAppleのアドバイザリに現れないもの")
    allc, mac = apple_cve_sets()
    over_nvd = nvd - prim
    print(f"    Apple Security Releases のCVE 全体{len(allc)}件 / macOSを対象とするもの{len(mac)}件")
    print(f"    DB-nvd 過剰検知 {len(over_nvd)}件のうち"
          f" macOS対象のアドバイザリに現れない {sum(1 for c in over_nvd if c not in mac)}件"
          f"（Apple全体で見ると {sum(1 for c in over_nvd if c not in allc)}件）")


if __name__ == "__main__":
    main()
