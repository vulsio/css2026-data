#!/usr/bin/env python3
"""C4: days from publication until a detection condition (CPE applicability) first appears,
measured from the Git history of the locally mirrored snapshots."""
import csv
import datetime as dt
import json
import os
import subprocess
import sys
import threading
from collections import defaultdict

SP = "/tmp/claude-1000/-home-mainek00n-github-github-com-vulsio-css2026-data/37e4581d-b165-4be5-a3b7-036152d3298a/scratchpad"
BASE = "/home/mainek00n/github/github.com/vulsio/css2026-data/ghcr.io/vulsio/vuls-data-db"
REPOS = {
    "NVD": (os.path.join(BASE, "vuls-data-raw-nvd-feed-cve-v2"), ["configurations"]),
    "VulnCheck": (os.path.join(BASE, "vuls-data-raw-vulncheck-nist-nvd2"),
                  ["configurations", "vcConfigurations"]),
}
# Git history starts 2025-06-26 (NVD) / 2025-08-06 (VulnCheck); use a common safe cutoff.
CUTOFF = {"NVD": "2025-07-01", "VulnCheck": "2025-08-15"}
SAMPLE_EVERY = int(sys.argv[1]) if len(sys.argv) > 1 else 25
MODE = sys.argv[2] if len(sys.argv) > 2 else "all"   # all | corpus | fortinet


def has_cond(blob, keys):
    try:
        d = json.loads(blob)
    except Exception:
        return None
    for k in keys:
        for cfg in d.get(k) or []:
            for n in cfg.get("nodes") or []:
                for m in n.get("cpeMatch") or []:
                    if m.get("vulnerable"):
                        return True
    return False


def commit_map(repo, wanted):
    """path -> [(date, commit)] oldest first, restricted to wanted paths."""
    out = defaultdict(list)
    p = subprocess.Popen(["git", "-C", repo, "log", "--name-only", "--reverse",
                          "--format=C|%H|%ad", "--date=short"],
                         stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
    cur = None
    for line in p.stdout:
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("C|"):
            _, h, d = line.split("|", 2)
            cur = (d, h)
        elif line in wanted:
            out[line].append(cur)
    p.wait()
    return out


def measure(name, cves_pub, every=None):
    repo, keys = REPOS[name]
    cut = CUTOFF[name]
    ev = SAMPLE_EVERY if every is None else every
    sel = {c: p for c, p in cves_pub.items() if p >= cut}
    sel = {c: p for i, (c, p) in enumerate(sorted(sel.items())) if i % ev == 0}
    wanted = {f"{c.split('-')[1]}/{c}.json": c for c in sel}
    print(f"[{name}] 対象 {len(sel)} 件（公開日 >= {cut}，{ev} 件ごとに抽出）",
          file=sys.stderr)
    cm = commit_map(repo, set(wanted))

    reqs, meta = [], []
    for path, cve in wanted.items():
        cs = cm.get(path) or []
        for d, h in cs:
            reqs.append(f"{h}:{path}")
            meta.append((cve, d))
    print(f"[{name}] blob 参照 {len(reqs)} 件", file=sys.stderr)

    proc = subprocess.Popen(["git", "-C", repo, "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1 << 22)

    def feed():
        # Must write from a separate thread: writing all requests up front while not
        # draining stdout deadlocks once the OS pipe buffers fill.
        try:
            proc.stdin.write(("\n".join(reqs) + "\n").encode())
            proc.stdin.close()
        except BrokenPipeError:
            pass

    threading.Thread(target=feed, daemon=True).start()

    first = {}
    seen = set()
    for cve, d in meta:
        hdr = proc.stdout.readline().decode()
        if not hdr or " " not in hdr:
            continue
        parts = hdr.split()
        if len(parts) < 3:
            continue
        size = int(parts[2])
        blob = proc.stdout.read(size)
        proc.stdout.read(1)
        seen.add(cve)
        if cve in first:
            continue
        if has_cond(blob, keys):
            first[cve] = d
    proc.wait()

    delays, censored = [], 0
    for cve in sel:
        if cve not in seen:
            continue
        if cve in first:
            try:
                delays.append((dt.date.fromisoformat(first[cve]) -
                               dt.date.fromisoformat(sel[cve])).days)
            except ValueError:
                pass
        else:
            censored += 1
    return delays, censored, len(seen)


def stats(delays):
    delays = sorted(delays)
    if not delays:
        return "n/a"
    def q(p):
        return delays[min(len(delays) - 1, int(len(delays) * p))]
    return (f"n={len(delays)} 中位数={q(.5)} 75%点={q(.75)} 90%点={q(.9)} 最大={delays[-1]} "
            f"／0日={sum(1 for d in delays if d<=0)} 7日超={sum(1 for d in delays if d>7)} "
            f"30日超={sum(1 for d in delays if d>30)}")


# ---------- corpus-wide (t0 = CVE published date in NVD) ----------
pub = {}
with open(f"{SP}/nvd.csv") as f:
    for r in csv.DictReader(f):
        if r["vulnStatus"] != "Rejected" and r["published"]:
            pub[r["id"]] = r["published"]

if MODE in ("all", "corpus"):
  print("### C4: 公開から検知条件（CPE適用条件）が初めて現れるまでの日数")
  print("### 起点は NVD の published．Git履歴の開始以降に公開されたものに限る．")
  for name in ("NVD", "VulnCheck"):
    d, cen, seen = measure(name, pub)
    tot = len(d) + cen
    print(f"{name:<10}: {stats(d)}")
    print(f"{'':<10}  観測 {seen}件中 付与済み {len(d)}件 / 打切り（本稿時点で未付与）{cen}件"
          f"（{100*cen/max(tot,1):.1f}%）")

# ---------- Fortinet-specific (t0 = Fortinet advisory publication) ----------
ftpub = {}
for root, _, files in os.walk(f"{SP}/vuls-data-raw-fortinet"):
    for fn in files:
        if not fn.endswith(".json"):
            continue
        with open(os.path.join(root, fn), "rb") as fh:
            d = json.load(fh)
        p = (d.get("published") or "")[:10]
        for v in d.get("vulnerabilities") or []:
            c = v.get("cve")
            if c and p and (c not in ftpub or p < ftpub[c]):
                ftpub[c] = p
print()
print("### C4（Fortinet）: Fortinetアドバイザリ公開日を起点とした付与遅延")
for name in ("NVD", "VulnCheck"):
    d, cen, seen = measure(name, ftpub, every=1)
    tot = len(d) + cen
    print(f"{name:<10}: {stats(d)}")
    print(f"{'':<10}  観測 {seen}件中 付与済み {len(d)}件 / 打切り {cen}件")
