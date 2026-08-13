#!/bin/sh
# Regenerate/verify the dataset manifest recorded in README.md.
# Usage:  sh data/analysis/dataset-manifest.sh [<data-root>]
# Default data root is ./ghcr.io/vulsio/vuls-data-db
root="${1:-ghcr.io/vulsio/vuls-data-db}"
printf '%-34s %-40s %-20s %s\n' source commit "committed(UTC)" json_files
for d in "$root"/*/; do
    d="${d%/}"; n=$(basename "$d")
    [ -d "$d/.git" ] || continue
    printf '%-34s %-40s %-20s %s\n' \
        "$n" \
        "$(git -C "$d" rev-parse HEAD)" \
        "$(git -C "$d" log -1 --format=%cI)" \
        "$(find "$d" -name '*.json' | wc -l | tr -d ' ')"
done
