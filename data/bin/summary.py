#!/usr/bin/env python3
"""slot 00〜03 の検知結果を突き合わせて表にする。

    python3 data/bin/summary.py            全ベンダ
    python3 data/bin/summary.py fortinet   ベンダを指定

一次データソース DB（slot 00）を基準に、NVD / VulnCheck / NVD+VulnCheck が
何を取りこぼし（漏れ）、何を余分に出しているか（過剰）を数える。
「正解」は一次データソースだという前提を置いた集計であることに注意。
"""

import json
import pathlib
import sys

DATA_DIR = pathlib.Path(__file__).resolve().parents[1]
RESULT_DATE = "2026-08-01"
RESULT_TZ = "+0900"
SLOTS = [("00", "一次DS"), ("01", "NVD"), ("02", "VulnCheck"), ("03", "NVD+VC")]


def result_dir(vendor, slot):
    return DATA_DIR / vendor / "results" / f"{RESULT_DATE}T00-00-{slot}{RESULT_TZ}"


def load(vendor, slot):
    """{サーバ名: 検知CVE IDの集合} を返す"""
    d = result_dir(vendor, slot)
    if not d.is_dir():
        raise SystemExit(f"{d} がありません。data/bin/detect.sh を実行してください")
    out = {}
    for f in sorted(d.glob("*.json")):
        r = json.loads(f.read_text())
        out[r["serverName"]] = set(r.get("scannedCves") or {})
    return out


def main(vendors):
    for vendor in vendors:
        per_slot = {slot: load(vendor, slot) for slot, _ in SLOTS}
        servers = sorted(per_slot["00"])

        print(f"\n## {vendor}")
        head = f"{'server':<24}" + "".join(f"{label:>12}" for _, label in SLOTS)
        print(head)
        print("-" * len(head))
        for s in servers:
            row = f"{s:<24}"
            for slot, _ in SLOTS:
                row += f"{len(per_slot[slot].get(s, set())):>12}"
            print(row)

        print()
        head = f"{'server':<24}{'比較対象':>12}{'一致':>8}{'漏れ':>8}{'過剰':>8}"
        print(head)
        print("-" * len(head))
        for s in servers:
            base = per_slot["00"].get(s, set())
            for slot, label in SLOTS[1:]:
                got = per_slot[slot].get(s, set())
                print(
                    f"{s:<24}{label:>12}{len(base & got):>8}"
                    f"{len(base - got):>8}{len(got - base):>8}"
                )


if __name__ == "__main__":
    args = sys.argv[1:]
    main(args if args else ["fortinet", "microsoft", "apple"])
