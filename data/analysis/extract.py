#!/usr/bin/env python3
"""Extract per-CVE detection-condition metadata from local NVD feed / VulnCheck NVD++ snapshots."""
import csv
import json
import os
import pathlib
import sys
from multiprocessing import Pool

# Data root: repository-root ghcr.io/ by default; VULS_DATA_ROOT overrides it so the
# same scripts can run against the copy under data/db/ used by the detection experiment.
BASE = os.environ.get("VULS_DATA_ROOT") or str(
    pathlib.Path(__file__).resolve().parents[2] / "ghcr.io/vulsio/vuls-data-db")
NVD = os.path.join(BASE, "vuls-data-raw-nvd-feed-cve-v2")
VC = os.path.join(BASE, "vuls-data-raw-vulncheck-nist-nvd2")
OUT = "/tmp/claude-1000/-home-mainek00n-github-github-com-vulsio-css2026-data/37e4581d-b165-4be5-a3b7-036152d3298a/scratchpad"


def cfg_stats(cfgs):
    """(n_nodes, n_cpematch, n_vulnerable, n_ranged) over a configurations array."""
    nodes = matches = vuln = ranged = 0
    for c in cfgs or []:
        for n in c.get("nodes") or []:
            nodes += 1
            for m in n.get("cpeMatch") or []:
                matches += 1
                if m.get("vulnerable"):
                    vuln += 1
                if any(k in m for k in ("versionStartIncluding", "versionStartExcluding",
                                        "versionEndIncluding", "versionEndExcluding")):
                    ranged += 1
    return nodes, matches, vuln, ranged


def do_nvd(year_dir):
    rows = []
    d = os.path.join(NVD, year_dir)
    for fn in os.listdir(d):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, fn), "rb") as f:
                r = json.load(f)
        except Exception:
            continue
        nodes, matches, vuln, ranged = cfg_stats(r.get("configurations"))
        aff = r.get("affected") or []
        # CNA-provided affected entries (CVE Record Format 5.x container), if any
        aff_items = sum(len(a.get("affectedData") or []) for a in aff)
        rows.append((
            r.get("id", ""),
            (r.get("published") or "")[:10],
            (r.get("lastModified") or "")[:10],
            r.get("vulnStatus") or "",
            r.get("sourceIdentifier") or "",
            nodes, matches, vuln, ranged,
            len(aff), aff_items,
        ))
    return rows


def do_vc(year_dir):
    rows = []
    d = os.path.join(VC, year_dir)
    for fn in os.listdir(d):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, fn), "rb") as f:
                r = json.load(f)
        except Exception:
            continue
        n1, m1, v1, r1 = cfg_stats(r.get("configurations"))
        n2, m2, v2, r2 = cfg_stats(r.get("vcConfigurations"))
        rows.append((
            r.get("id", ""),
            (r.get("published") or "")[:10],
            (r.get("lastModified") or "")[:10],
            r.get("vulnStatus") or "",
            m1, v1, r1,          # mirrored NVD configurations
            m2, v2, r2,          # VulnCheck's own enrichment
            len(r.get("vcVulnerableCPEs") or []),
        ))
    return rows


def main():
    years = sorted(y for y in os.listdir(NVD) if y.isdigit())
    with Pool(16) as p:
        nvd_rows = [r for chunk in p.map(do_nvd, years) for r in chunk]
    with open(os.path.join(OUT, "nvd.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "published", "lastModified", "vulnStatus", "source",
                    "nodes", "matches", "vulnerable", "ranged", "affSrc", "affItems"])
        w.writerows(nvd_rows)
    print("nvd rows:", len(nvd_rows), file=sys.stderr)

    years = sorted(y for y in os.listdir(VC) if y.isdigit())
    with Pool(16) as p:
        vc_rows = [r for chunk in p.map(do_vc, years) for r in chunk]
    with open(os.path.join(OUT, "vc.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "published", "lastModified", "vulnStatus",
                    "nvdMatches", "nvdVuln", "nvdRanged",
                    "vcMatches", "vcVuln", "vcRanged", "vcCPEs"])
        w.writerows(vc_rows)
    print("vc rows:", len(vc_rows), file=sys.stderr)


if __name__ == "__main__":
    main()
