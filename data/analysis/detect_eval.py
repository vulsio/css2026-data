#!/usr/bin/env python3
"""7章：一次データソースDB / NVD / VulnCheck / NVD+VulnCheck の検知結果の比較。

data/<vendor>/results/<slot>/*.json（data/bin/detect.sh の出力）を読み、
slot 00（一次データソースDB）を基準に一致・未検知・過剰検知を数える。

1台のスキャン対象に複数の製品を宣言しているため（macOS と Safari、
Windows と Microsoft Edge）、検知を製品単位に割り当ててから集計する。
CPE で検知したものは cpeURIs から、Microsoft の slot 00（KB による検知）は
affectedPackages の名前から製品を決める。

    python3 data/analysis/detect_eval.py
"""

import collections
import json
import pathlib
import re

BASE = pathlib.Path(__file__).resolve().parents[1]
SLOTS = [("00", "primary"), ("01", "NVD"), ("02", "VulnCheck"), ("03", "NVD+VC")]
RESULT_DATE, RESULT_TZ = "2026-08-01", "+0900"

NVD_RAW = BASE / "db/ghcr.io/vulsio/vuls-data-db/vuls-data-raw-nvd-feed-cve-v2"
# ベンダ自身のCNAとしての sourceIdentifier。未検知CVEを「自社採番か組込み部品か」に分ける
OWN_CNA = {
    "fortinet": {"psirt@fortinet.com"},
    "microsoft": {"secure@microsoft.com"},
    "apple": {"product-security@apple.com"},
    "cisco": {"psirt@cisco.com", "talos-cna@cisco.com"},
}


def discover_targets():
    """data/<vendor>/results/<slot00>/ から (vendor, server) を集める"""
    out = []
    for vendor in sorted(d.name for d in BASE.iterdir() if d.is_dir() and d.name != "db"):
        slot0 = BASE / vendor / "results" / f"{RESULT_DATE}T00-00-00{RESULT_TZ}"
        if not slot0.is_dir():
            continue
        for f in sorted(slot0.glob("*.json")):
            out.append((vendor, f.stem))
    return out


TARGETS = discover_targets()

_cna_cache = {}


def cna_of(cve):
    """NVDの sourceIdentifier（採番CNA）。NVDに無ければ None"""
    if cve not in _cna_cache:
        y = year(cve)
        try:
            _cna_cache[cve] = json.loads(
                (NVD_RAW / str(y) / f"{cve}.json").read_text()
            ).get("sourceIdentifier")
        except OSError:
            _cna_cache[cve] = None
    return _cna_cache[cve]


def product_of_cpe(uri):
    """cpe:/o:apple:macos:14.7.4 -> apple:macos

    apple:mac_os_x と apple:macos は同じOSの表記ゆれなので同一製品に寄せる。
    Apple自身は macos しか使わないが、NVDは古いCVEを mac_os_x に置いており、
    分けたままだと表記ゆれがそのままNVDの未検知として計上されてしまう。
    """
    parts = uri.split(":")
    if len(parts) < 4:
        return None
    vendor, product = parts[2], parts[3]
    if product == "mac_os_x":
        product = "macos"
    return f"{vendor}:{product}"


def os_product_of(vendor, server):
    """スキャン設定で宣言したOSのCPE製品名（Microsoft の KB 検知の割り当て先）"""
    path = (
        BASE / vendor / "results" / f"{RESULT_DATE}T00-00-01{RESULT_TZ}" / f"{server}.json"
    )
    conf = json.loads(path.read_text())["config"]["scan"]["servers"][server]
    for uri in conf.get("cpeNames") or []:
        if uri.startswith("cpe:/o:"):
            return product_of_cpe(uri)
    return None


def product_of_pkg(name, os_product):
    """Microsoft の KB 検知は affectedPackages の名前で製品を決める"""
    if name.startswith("Microsoft Edge"):
        return "microsoft:edge_chromium"
    if name.startswith("Windows"):
        return os_product
    return None


def load(vendor, slot, server, os_product):
    """{製品: 検知CVE IDの集合} と、製品を決められなかった件数を返す"""
    path = (
        BASE / vendor / "results" / f"{RESULT_DATE}T00-00-{slot}{RESULT_TZ}" / f"{server}.json"
    )
    r = json.loads(path.read_text())
    out, unknown = collections.defaultdict(set), 0
    for cve, v in (r.get("scannedCves") or {}).items():
        prods = {p for u in (v.get("cpeURIs") or []) if (p := product_of_cpe(u))}
        if not prods:
            prods = {
                p
                for a in (v.get("affectedPackages") or [])
                if (p := product_of_pkg(a.get("name", ""), os_product))
            }
        if not prods:
            unknown += 1
            continue
        for p in prods:
            out[p].add(cve)
    return out, unknown


def year(cve):
    m = re.match(r"CVE-(\d{4})-", cve)
    return int(m.group(1)) if m else 0


def bucket(y):
    return "-2023" if y <= 2023 else str(y)


def pct(n, d):
    return f"{100.0 * n / d:.1f}" if d else "---"


def main():
    data, unknowns = {}, {}
    for vendor, server in TARGETS:
        os_product = os_product_of(vendor, server)
        for slot, _ in SLOTS:
            data[(server, slot)], unknowns[(server, slot)] = load(
                vendor, slot, server, os_product
            )

    products = {}
    for _, server in TARGETS:
        seen = []
        for slot, _ in SLOTS:
            for p in data[(server, slot)]:
                if p not in seen:
                    seen.append(p)
        products[server] = sorted(seen)

    print("# 製品単位の検知件数")
    print(f"{'server':<22}{'product':<30}" + "".join(f"{lab:>10}" for _, lab in SLOTS))
    for _, server in TARGETS:
        for p in products[server]:
            row = f"{server:<22}{p:<30}"
            for slot, _ in SLOTS:
                row += f"{len(data[(server, slot)].get(p, set())):>10}"
            print(row)
    print(
        "製品を決められなかった検知（Microsoft slot00 の KB のみの行）: "
        + ", ".join(
            f"{s}/{sl}={n}" for (s, sl), n in sorted(unknowns.items()) if n
        )
    )

    print("\n# 一次データソースDBを基準とした一致・未検知・過剰検知")
    print(
        f"{'server':<22}{'product':<30}{'対象':<10}"
        f"{'基準':>7}{'一致':>7}{'未検知':>8}{'過剰':>7}{'未検知率':>9}{'過剰率':>8}"
    )
    for _, server in TARGETS:
        for p in products[server]:
            base = data[(server, "00")].get(p, set())
            if not base:
                continue
            for slot, lab in SLOTS[1:]:
                got = data[(server, slot)].get(p, set())
                miss, extra = base - got, got - base
                print(
                    f"{server:<22}{p:<30}{lab:<10}"
                    f"{len(base):>7}{len(base & got):>7}{len(miss):>8}{len(extra):>7}"
                    f"{pct(len(miss), len(base)):>9}{pct(len(extra), len(got)):>8}"
                )

    print("\n# 未検知CVEの公開年分布（未検知/基準）")
    for _, server in TARGETS:
        for p in products[server]:
            base = data[(server, "00")].get(p, set())
            if not base:
                continue
            base_y = collections.Counter(bucket(year(c)) for c in base)
            for slot, lab in SLOTS[1:]:
                miss_y = collections.Counter(
                    bucket(year(c)) for c in base - data[(server, slot)].get(p, set())
                )
                cells = "  ".join(
                    f"{b}:{miss_y[b]}/{base_y[b]}({pct(miss_y[b], base_y[b])}%)"
                    for b in sorted(base_y)
                )
                print(f"{server:<22}{p:<30}{lab:<10}{cells}")

    print("\n# 未検知CVEの採番元（自社CNA採番か、組込み部品として他者が採番したものか）")
    print(
        f"{'server':<22}{'product':<30}{'対象':<10}"
        f"{'未検知':>7}{'自社採番':>9}{'他者採番':>9}{'他者の割合':>11}"
    )
    for vendor, server in TARGETS:
        own = OWN_CNA.get(vendor, set())
        for p in products[server]:
            base = data[(server, "00")].get(p, set())
            if not base:
                continue
            for slot, lab in SLOTS[1:]:
                miss = base - data[(server, slot)].get(p, set())
                o = sum(1 for c in miss if cna_of(c) in own)
                print(
                    f"{server:<22}{p:<30}{lab:<10}"
                    f"{len(miss):>7}{o:>9}{len(miss) - o:>9}"
                    f"{pct(len(miss) - o, len(miss)):>11}"
                )

    print("\n# VulnCheckの上積み（NVD+VC - NVD）と、verified抑制で落ちた分（VC - NVD+VC）")
    for _, server in TARGETS:
        for p in products[server]:
            base = data[(server, "00")].get(p, set())
            nvd = data[(server, "01")].get(p, set())
            vc = data[(server, "02")].get(p, set())
            both = data[(server, "03")].get(p, set())
            add, sup = both - nvd, vc - both
            print(
                f"{server:<22}{p:<30}"
                f"上積み={len(add):>5}(一次DBにもある={len(add & base):>5})  "
                f"抑制={len(sup):>5}(一次DBにもある={len(sup & base):>5})"
            )


if __name__ == "__main__":
    main()
