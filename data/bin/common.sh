#!/bin/sh
# data/bin/*.sh から読み込む共通定義。単体では実行しない。
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DATA_DIR="$REPO_ROOT/data"
DB_DIR="$DATA_DIR/db"

# 検知に使う vuls（v1）。リポジトリに同梱してある。
VULS="${VULS:-$DATA_DIR/vuls}"

# 検証対象ベンダ。増やすときは data/<vendor>/results/<slot>/ にスキャン結果を置き、
# data/db/vuls.<vendor>.db.zst を用意して、ここに足す（一次データソース DB 名 = ベンダ名）。
VENDORS="${VENDORS:-fortinet microsoft apple cisco openssh}"

# results/ のスロット。slot:db の対応で、slot が結果ディレクトリ名の連番になる。
#   00 = 一次データソース DB / 01 = NVD / 02 = VulnCheck / 03 = NVD+VulnCheck
SLOTS="00:primary 01:nvd 02:vulncheck 03:nvd-vulncheck"

# results/ のディレクトリ名に使う固定日時（実行日時に依存させないための固定値）
RESULT_DATE="${RESULT_DATE:-2026-08-01}"
RESULT_TZ="${RESULT_TZ:-+0900}"

log() { printf '==> %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# slot 番号から results/ のディレクトリ名を返す
slot_dirname() {
	printf '%sT00-00-%s%s\n' "$RESULT_DATE" "$1" "$RESULT_TZ"
}

# vendor と slot の db 名から、使う vuls DB 名を返す（primary はベンダ名そのもの）
slot_db() {
	case $2 in
	primary) printf '%s\n' "$1" ;;
	*) printf '%s\n' "$2" ;;
	esac
}

# 使う DB 名を重複なく列挙する
all_dbs() {
	for _v in $VENDORS; do
		for _s in $SLOTS; do
			slot_db "$_v" "${_s#*:}"
		done
	done | awk '!seen[$0]++'
}
