#!/bin/sh
# commit してある data/db/vuls.*.db.zst を展開する。
#
#   sh data/bin/unpack-db.sh          必要なものだけ（既に展開済みなら飛ばす）
#   sh data/bin/unpack-db.sh --force  全部展開し直す
#
# 展開後の .db は data/db/.gitignore で除外してあるので commit されない。
set -eu
. "$(dirname "$0")/common.sh"

command -v zstd >/dev/null 2>&1 || die "zstd が必要です"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

for db in $(all_dbs); do
	zst="$DB_DIR/vuls.$db.db.zst"
	out="$DB_DIR/vuls.$db.db"
	[ -f "$zst" ] || die "$zst がありません"

	# zstd は展開時に元ファイルの mtime を引き継ぐので、同じか新しければ展開済みとみなす
	if [ "$FORCE" -eq 0 ] && [ -f "$out" ] && [ ! "$out" -ot "$zst" ]; then
		log "skip vuls.$db.db (展開済み)"
		continue
	fi

	log "unpack vuls.$db.db"
	zstd -d -f -q -o "$out" "$zst"
done

# 検知に使う vuls 本体も同じ要領で展開する
if [ -f "$DATA_DIR/vuls.zst" ]; then
	if [ "$FORCE" -eq 1 ] || [ ! -f "$VULS" ] || [ "$VULS" -ot "$DATA_DIR/vuls.zst" ]; then
		log "unpack vuls"
		zstd -d -f -q -o "$VULS" "$DATA_DIR/vuls.zst"
		chmod +x "$VULS"
	else
		log "skip vuls (展開済み)"
	fi
fi

log "done"
ls -l "$DB_DIR"/vuls.*.db
