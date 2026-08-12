#!/bin/sh
# slot ごとに別の DB で検知し、data/<vendor>/results/<slot>/*.json を上書きする。
#
#   sh data/bin/detect.sh            全ベンダ
#   sh data/bin/detect.sh fortinet   ベンダを指定
#
#   slot 00 = 一次データソース DB（vuls.<vendor>.db）
#   slot 01 = NVD               （vuls.nvd.db）
#   slot 02 = VulnCheck         （vuls.vulncheck.db）
#   slot 03 = NVD + VulnCheck   （vuls.nvd-vulncheck.db）
#
# スキャン結果（scannedCves 以外）は 4 つの slot で共通なので、差は DB だけになる。
# 先に data/bin/unpack-db.sh を実行しておくこと。
#
# data/<vendor>/config.<db>.toml はこのスクリプトが生成する（手で編集しない）。
# 設定中のパスはリポジトリルートからの相対なので、必ずルートを cwd にして実行する。
set -eu
. "$(dirname "$0")/common.sh"

[ -x "$VULS" ] || die "vuls が見つかりません ($VULS)"

TARGETS=${*:-$VENDORS}

for vendor in $TARGETS; do
	[ -d "$DATA_DIR/$vendor" ] || die "data/$vendor がありません"

	for slot_spec in $SLOTS; do
		slot=${slot_spec%%:*}
		db=$(slot_db "$vendor" "${slot_spec#*:}")

		[ -f "$DB_DIR/vuls.$db.db" ] ||
			die "data/db/vuls.$db.db がありません。先に data/bin/unpack-db.sh を実行してください"

		ts=$(slot_dirname "$slot")
		[ -d "$DATA_DIR/$vendor/results/$ts" ] ||
			die "data/$vendor/results/$ts がありません"

		cat >"$DATA_DIR/$vendor/config.$db.toml" <<EOF
# data/bin/detect.sh が生成。手で編集しない。
[vuls2]
repository = "ghcr.io/vulsio/vuls-nightly-db:0"
path = "data/db/vuls.$db.db"
skipUpdate = true
EOF

		# -results-dir は絶対パスでないと弾かれる。config 内の DB パスは
		# リポジトリルートからの相対なので、cwd をルートに固定して実行する。
		log "detect $vendor slot $slot with vuls.$db.db"
		(cd "$REPO_ROOT" && "$VULS" report \
			-config="data/$vendor/config.$db.toml" \
			-results-dir="$DATA_DIR/$vendor/results" \
			-to-localfile \
			-format-json \
			"$ts")
	done
done

log "done"
