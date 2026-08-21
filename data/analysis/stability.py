#!/usr/bin/env python3
"""3.5節：いったん付与された検知条件が維持されるかを Git 履歴から測る。

vuls-data-raw-vulncheck-nist-nvd2 は NVD 由来の configurations と VulnCheck 独自の
vcConfigurations / vcVulnerableCPEs を同じファイルに持つので、同一の履歴から
両者の安定性を比べられる。製品集合は part:vendor:product で見る（版の揺れではなく
「製品が出入りするか」を測るため）。

    VULS_DATA_ROOT=data/db/ghcr.io/vulsio/vuls-data-db python3 data/analysis/stability.py
"""

import collections
import json
import os
import pathlib
import subprocess
import sys

BASE = os.environ.get("VULS_DATA_ROOT") or str(
    pathlib.Path(__file__).resolve().parents[1] / "db/ghcr.io/vulsio/vuls-data-db")
REPO = os.path.join(BASE, "vuls-data-raw-vulncheck-nist-nvd2")

# 層別標本：変更回数の多いCVEほど振動しやすいので、層ごとに標本数を割り当てる。
# 3回未満しか変更されていないCVEは定義上3回以上の振動をしえないので層に含めない。
STRATA = [("300回以上", 300, None, 88), ("100-299回", 100, 299, 39),
          ("10-99回", 10, 99, 400), ("3-9回", 3, 9, 2000)]
EXAMPLE = ("2015/CVE-2015-4000.json", "suse:suse_linux_enterprise_server")


def history():
    """{path: [commit, ...]}（古い順）"""
    out = subprocess.run(["git", "-C", REPO, "log", "--format=C %H", "--name-only"],
                         capture_output=True, text=True).stdout
    per = collections.defaultdict(list)
    cur = None
    for line in out.split("\n"):
        if line.startswith("C "):
            cur = line[2:]
        elif line.endswith(".json"):
            per[line].append(cur)
    for p in per:
        per[p].reverse()
    return per


def blobs(refs):
    """git cat-file --batch でまとめて読む（1リビジョンずつ git show するより速い）"""
    p = subprocess.run(["git", "-C", REPO, "cat-file", "--batch"],
                       input=("\n".join(refs) + "\n").encode(), capture_output=True)
    out, i, res = p.stdout, 0, []
    for _ in refs:
        nl = out.index(b"\n", i)
        head = out[i:nl].split()
        if len(head) < 3:
            res.append(None)
            i = nl + 1
            continue
        size = int(head[2])
        res.append(out[nl + 1:nl + 1 + size])
        i = nl + 1 + size + 1
    return res


def products(doc, field):
    s = set()
    for cfg in doc.get(field) or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                p = (m.get("criteria") or "").split(":")
                if len(p) > 5:
                    s.add(f"{p[3]}:{p[4]}")
    return s


def vc_products(doc):
    s = products(doc, "vcConfigurations")
    for cpe in doc.get("vcVulnerableCPEs") or []:
        p = cpe.split(":")
        if len(p) > 5:
            s.add(f"{p[3]}:{p[4]}")
    return s


def series(path, commits):
    """各リビジョンの (NVD製品集合, VulnCheck製品集合)"""
    out = []
    for raw in blobs([f"{c}:{path}" for c in commits]):
        if raw is None:
            continue
        try:
            d = json.loads(raw)
        except Exception:
            continue
        out.append((products(d, "configurations"), vc_products(d)))
    return out


def flips(seq):
    return sum(1 for i in range(1, len(seq)) if seq[i] != seq[i - 1])


def main():
    per = history()
    print(f"### 対象: {REPO}")
    print(f"### コミット {len(set(c for v in per.values() for c in v))}件 / ファイル {len(per)}件")

    # 例：CVE-2015-4000 の特定製品の出入り
    path, target = EXAMPLE
    commits = per.get(path, [])
    seq = series(path, commits)
    present = [target in vc for _, vc in seq]
    nvd_present = [target in nv for nv, _ in seq]
    print(f"\n[3.5] {path} の {target}")
    print(f"    このCVEが更新されたスナップショット {len(seq)}回")
    print(f"    VulnCheck側: 出現 {sum(present)}回 / 有無の入れ替わり {flips(present)}回")
    print(f"    NVD側      : 出現 {sum(nvd_present)}回 / 有無の入れ替わり {flips(nvd_present)}回")

    # 層別標本
    by_count = collections.defaultdict(list)
    for p, cs in per.items():
        by_count[len(cs)].append(p)
    print("\n[3.5] 層別標本による推定（製品集合が3回以上入れ替わるCVE）")
    total_est = nvd_unstable = nvd_oscillating = sampled_total = 0
    for label, lo, hi, quota in STRATA:
        pool = sorted(p for n, ps in by_count.items()
                      if n >= lo and (hi is None or n <= hi) for p in ps)
        if not pool:
            continue
        step = max(1, len(pool) // quota)
        sample = pool[::step][:quota]
        osc = nvd_chg = nvd_osc = 0
        for p in sample:
            s = series(p, per[p])
            if flips([vc for _, vc in s]) >= 3:
                osc += 1
            f = flips([nv for nv, _ in s])
            nvd_chg += f > 0
            nvd_osc += f >= 3
        est = len(pool) * osc / len(sample)
        total_est += est
        sampled_total += len(sample)
        nvd_unstable += nvd_chg
        nvd_oscillating += nvd_osc
        print(f"    変更{label:9s} 母数{len(pool):7d}件  標本{len(sample):5d}件中"
              f" VC振動{osc:5d}件  推定{est:9.0f}件"
              f"  （NVD側: 変化{nvd_chg:5d}件 / 3回以上{nvd_osc:4d}件）")
    nfiles = len(per)
    print(f"    合計推定 {total_est:.0f}件（全 {nfiles}件の {100 * total_est / nfiles:.1f}%）")
    print(f"    NVDの configurations: 標本{sampled_total}件中"
          f" 製品集合が変化{nvd_unstable}件 / 3回以上入れ替わり{nvd_oscillating}件")


if __name__ == "__main__":
    main()
