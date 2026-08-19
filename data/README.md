# data/ — 検知比較の実験一式

同じスキャン結果を 4 つの脆弱性 DB にかけ、検知条件の供給源の違いが検知結果に
どう出るかを見るためのデータとスクリプト。

| slot | 結果ディレクトリ | 使う DB | 中身 |
|---|---|---|---|
| 00 | `<vendor>/results/2026-08-01T00-00-00+0900/` | `db/vuls.<vendor>.db` | 一次データソース |
| 01 | `…T00-00-01+0900/` | `db/vuls.nvd.db` | NVD |
| 02 | `…T00-00-02+0900/` | `db/vuls.vulncheck.db` | VulnCheck NVD++ |
| 03 | `…T00-00-03+0900/` | `db/vuls.nvd-vulncheck.db` | NVD + VulnCheck |

ディレクトリ名の日時に意味はない。vuls v1 の `report` が結果ディレクトリを日時で
選ぶため、同じスキャン結果を 4 つに複製して別々の DB で検知させるための連番である。
`scannedCves` 以外は 4 つとも同一なので、差分はすべて DB の違いに由来する。

対象は Fortinet / Cisco / Microsoft / Apple / OpenSSH の 5 ベンダ。

### slot 02 と slot 03 は足し算にならない

vuls は CPE のデータソースを 2 つに分けており、VulnCheck NVD++（と JVN）は
「信頼度の低い」側に置かれている（`detector/vuls2/vuls2.go` の
`verifiedCPESources` / `isSuppressedCPESource`）。ある CVE について
verified 側（NVD、Fortinet、Cisco、PaloAlto、Apple）が `part:vendor:product` を
**定義してさえいれば**、たとえそのバージョン範囲がスキャン対象に一致せず非検知でも、
VulnCheck 側の同じ製品の検知は捨てられる（`collectVerifiedProducts` と
`suppress`。go-cve-dictionary の `isCpeURIAlsoDefinedInVerifiedDataSource` の再現）。

そのため各 slot の意味は次のようになる。

- slot 02 は DB に verified ソースが 1 つも入っていないので抑制が働かない。
  **VulnCheck のデータそのものが持つ検知力**を測っている。
- slot 03 は NVD が verified 側として抑制をかける。
  **NVD+VulnCheck を積んだ vuls の実際の挙動**であり、slot 01 と slot 02 の和集合ではない。
  実際 fortios_7-0-1 では slot 02 が 188 件なのに slot 03 は 152 件で、slot 01 の 151 件から
  1 件しか増えていない。

「VulnCheck の過剰検知」を論じるときは、どちらの意味で数えているかを明示する必要がある。

## やり直し方

```sh
sh data/bin/unpack-db.sh          # commit 済みの .zst を展開（初回のみ）
sh data/bin/detect.sh             # 4 slot ぶん検知し直す
python3 data/bin/summary.py       # 結果を突き合わせて表示
```

ベンダを指定するなら `sh data/bin/detect.sh fortinet` のように引数を渡す。

- 検知に使う vuls（v1）は `data/vuls.zst` として commit してある。`unpack-db.sh` が
  DB と一緒に `data/vuls` へ展開して実行権を付けるので、ビルドは不要
  （別のビルドを使うなら `VULS=/path/to/vuls sh data/bin/detect.sh`）。
  自分でビルドしたい場合は後述の「vuls をビルドし直す」を参照。
- `data/<vendor>/config.<db>.toml` は `detect.sh` が毎回生成する。DB パスは
  リポジトリルートからの相対にしてあるので clone 先に依存しない（そのため
  `detect.sh` はルートを cwd にして vuls を呼ぶ）。手で編集しても上書きされる。
- `detect.sh` は結果 JSON を上書きする。検知内容以外に `reportedBy`（実行ホスト名）と
  `reportedRevision`（vuls のビルドID）も入るので、別マシンで流すとこの 2 つは変わる。

## スキャン結果について

スキャンは済んでいて、やり直す必要はない。`<vendor>/results/**.json` の
`config.scan.servers` に、どのサーバをどの CPE で見立てたかが残っている。

- Fortinet / Cisco / Apple / OpenSSH、および Microsoft の slot 01〜03 は vuls v1 の
  pseudo スキャン（`cpeNames` を宣言しただけの仮想サーバ）。
- Microsoft の slot 00 だけは実機 Windows のスキャン結果。適用済み KB で検知する
  ため CPE では代用できず、実機を用意しない限り取り直せない。
  ここを pseudo スキャンで上書きしないこと。

## DB を作り直す

通常は不要（`db/vuls.*.db.zst` を commit してある）。スナップショットを新しくする
ときだけ、`data/sources.tsv` の commit を更新して次を流す。

必要なツール:

- `vuls-data-update` … `nightly` の `a1fb26a2`（Apple #917/#939/#940、OpenSSH #928、
  Fortinet 補完表 #941 がすべて入っている）。
- `vuls`（nightly / vuls2）… `github.com/MaineK00n/vuls2`
  （`663ae1050b94a610d00c569a3dab1503a07e8a65`）。DB の init / add / compress に使う。

```sh
# 1. sources.tsv の tag / commit ぶんだけ dotgit を取得する
vuls-data-update dotgit pull --dir data/db --checkout <commit> --restore \
    ghcr.io/vulsio/vuls-data-db:<tag>

# 2. kind=raw の行だけ、手元で extract する（apple と fortinet-cvrf）
vuls-data-update extract apple-security-releases \
    data/db/ghcr.io/vulsio/vuls-data-db/vuls-data-raw-apple-security-releases \
    --dir data/db/ghcr.io/vulsio/vuls-data-db/vuls-data-extracted-apple-security-releases
vuls-data-update extract fortinet-cvrf \
    data/db/ghcr.io/vulsio/vuls-data-db/vuls-data-raw-fortinet-cvrf \
    --dir data/db/ghcr.io/vulsio/vuls-data-db/vuls-data-extracted-fortinet-cvrf

# 3. DB ごとに、sources.tsv の上の行から順に投入して圧縮する
vuls db init     --dbpath data/db/vuls.<name>.db
vuls db add      --dbpath data/db/vuls.<name>.db data/db/ghcr.io/vulsio/vuls-data-db/<extracted tag>
vuls db compress --dbpath data/db/vuls.<name>.db   # .db を compact し .db.zst を作る
```

`ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-apple-security-releases` は空の
プレースホルダなので、apple は raw から extract する必要がある。fortinet-cvrf も
raw から取る。従来ここで固定していた extracted アーティファクトの commit
（`b915804`、2026-08-10）は #941 の補完表の作り直しより前のもので、5 章の数値は
作り直したあとの抽出器で算出しているためである（`data/analysis/fortinet_extracted.out`
も同じ）。
OpenSSH は raw の `raw/` をモデルによる変換で作る構成のため、fetch だけでは
再生成できない（詳細は vuls-data-update の PR #928 を参照）。

## vuls をビルドし直す

通常は不要（`data/vuls.zst` を commit してある）。同梱バイナリは
`-trimpath -ldflags "-s -w"` で strip したもので、strip の有無で検知結果は変わらない
ことを確認している。

Apple と OpenSSH の検知に必要な PR はすべて上流にマージされたので、ブランチを
マージして回る必要はなくなった。

| リポジトリ | commit | 含まれる PR |
|---|---|---|
| MaineK00n/vuls-data-update | `a1fb26a2`（nightly） | #917 / #939 / #940 / #928 / #941 |
| future-architect/vuls | `386ec577`（master） | #2635 / #2636 |

```sh
git -C vuls switch --detach 386ec57759dd
CGO_ENABLED=0 GOEXPERIMENT=jsonv2 go build -trimpath -ldflags "-s -w" -o vuls ./cmd/vuls
```

同梱の `data/vuls.zst` は、この 2 つが上流にマージされる前に同じ内容のブランチを
マージしてビルドしたものである。

## ファイル

```
data/
  vuls.zst                検知に使う vuls v1 のバイナリ（unpack-db.sh が展開）
  sources.tsv             各 DB がどの tag / commit から作られたかの記録
  db/
    vuls.*.db.zst         commit 済みの DB（unpack-db.sh で展開）
    vuls.*.db             展開後の DB（.gitignore 済み）
    ghcr.io/              dotgit の取得先（.gitignore 済み）
  <vendor>/
    config.*.toml         detect.sh が生成（.gitignore 済み）
    results/<slot>/*.json スキャン結果 兼 検知結果
  bin/
    common.sh             共通定義（ベンダ・slot・パス）
    unpack-db.sh          .db.zst と vuls.zst を展開
    detect.sh             slot ごとに DB を変えて検知
    summary.py            slot 00 を基準に漏れ／過剰を集計
```

## OpenSSH のデータについて

`vuls.openssh.db` の元になる extracted データは ghcr に存在しない。
vuls-data-update の `fetch openssh-security` が `origin/security.html` と変換手順
（`SKILL.md`）を出力し、そこから `raw/` をモデルによる変換で作る構成のためである。
`data/sources.tsv` では kind を `local` とし、commit hash の代わりに `-` を置いている。

生成された `raw/` は `data/db/ghcr.io/vulsio/vuls-data-db/vuls-data-raw-openssh-security/`
に置いてある（`.gitignore` 対象）。再取得するには vuls-data-update の PR #928 を参照。
