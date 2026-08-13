# css2026-data

CSS2026 OWSトラック投稿論文「脆弱性検知条件の供給源の再検討」の原稿と、測定に用いたデータ・スクリプト。

| | |
|---|---|
| 原稿（LaTeX） | [`docs/`](docs/) — `docs/css.tex` が本体。`cd docs && latexmk css.tex` でビルドする |
| 集計スクリプト | [`data/analysis/`](data/analysis/) — 3章の調査と、5章の検知結果の集計 |
| 検知実験一式 | [`data/`](data/) — DB・スキャン結果・検知スクリプト。詳細は [`data/README.md`](data/README.md) |

論文は本文8ページ（参考文献含む）で、章立ては次のとおり。

| 章 | 内容 | 対応する成果物 |
|---|---|---|
| 3 | 検知条件の供給実態の定量調査 | `data/analysis/` の集計スクリプト |
| 4 | 一次データソースの構造化（LLMの3パターン） | vuls-data-update の各PR（原稿の参考文献を参照） |
| 5 | 検知精度への影響の評価 | `data/` の検知実験 + `data/analysis/detect_eval.py` |

## データのスナップショットは2系統ある

同じ `ghcr.io/vulsio/vuls-data-db` を使うが、**用途ごとに別のスナップショットを固定している**。

| 用途 | 形式 | 記録場所 | 実体の置き場所 |
|---|---|---|---|
| 3章の集計 | raw アーティファクト | 下記の表 | `ghcr.io/vulsio/vuls-data-db/`（`.gitignore` 済み） |
| 5章の検知 | extracted から作った vuls DB | [`data/sources.tsv`](data/sources.tsv) | `data/db/vuls.*.db.zst`（**commit 済み**） |

検知だけをやり直すなら、commit してある `.db.zst` を展開すれば足りる（`data/README.md` を参照）。
以下の表が要るのは、3章の集計をやり直すときだけである。

### 3章の集計に用いたスナップショット

論文中の数値はすべて下記から算出している。データ本体は `.gitignore` により本リポジトリには含めないため、**再検証にはこのcommit hashを指定して取得すること**。

- 取得先: `ghcr.io/vulsio/vuls-data-db`（各行の source がOCIアーティファクトのタグ名）
- 配置先: `ghcr.io/vulsio/vuls-data-db/<source>/`（Zstandardで展開すると `.git/` のみのディレクトリになるので、`git -C <dir> checkout <commit>` で任意時点に復元できる）
- 取得日: 2026年7月30日

| source | commit | committed (UTC) | json files |
|---|---|---|---|
| vuls-data-raw-nvd-feed-cve-v2 | `f34a9c3b16c23d99f141811666380ece8b99170d` | 2026-07-30T01:55:17Z | 371,416 |
| vuls-data-raw-vulncheck-nist-nvd2 | `cc430fb1178daa5cafc1beccc7877bc970b67007` | 2026-07-30T01:14:05Z | 371,393 |
| vuls-data-raw-fortinet-cvrf | `41b12c74848c6ab6258b9539b62f5996f82412c8` | 2026-07-23T02:23:51Z | 1,119 |
| vuls-data-raw-fortinet-csaf | `cedaf51587c327b1f67ddb3b0e61259262627091` | 2026-07-17T02:00:00Z | 173 |
| vuls-data-raw-cisco-json | `5fdc0f3ea08d0d2ed2d939ebfb70fa4365e09710` | 2026-07-30T01:12:33Z | 5,309 |
| vuls-data-raw-mitre-cve-v5 | `7854fd090be5c7307a86fca8c9fe0107a4dffbd7` | 2026-07-30T02:38:13Z | 371,793 |
| vuls-data-raw-microsoft-cvrf | `627884e9827484567f273256cf25f8501713b536` | 2026-07-30T01:41:22Z | 26,883 |
| vuls-data-raw-microsoft-msuc | `ab559b447e877530b6265e202856d46777322cbe` | 2026-07-30T03:33:51Z | 6,700 |
| vuls-data-raw-microsoft-bulletin | `3dd51f6ac89db13efedf13fadd1b7f99b174bc5d` | 2026-04-01T04:02:55Z | 1,371 |
| vuls-data-raw-microsoft-wsusscn2 | `67e3ade4ceb4cc0094a6f00e9171da72feaf383c` | 2026-07-15T02:30:55Z | 436,435 |
| vuls-data-raw-enisa-euvd-list | `cf45520703e50b6976c7883b03fc9c04e20b85a2` | 2026-07-28T18:16:50Z | 370,571 |

この表は下記で再生成・照合できる。

```sh
sh data/analysis/dataset-manifest.sh
```

このうち3章の数値に直接使っているのは次の5つである。

| source | 用いた箇所 |
|---|---|
| vuls-data-raw-nvd-feed-cve-v2 | 3.2節・3.3節、3.4節と3.5節の比較対象、C4のGit履歴 |
| vuls-data-raw-vulncheck-nist-nvd2 | 同上 |
| vuls-data-raw-fortinet-cvrf / -csaf | 3.4節・3.5節（一次データソースの基準） |
| vuls-data-raw-cisco-json | 3.4節のC1、3.5節のC4 |

mitre-cve-v5、enisa-euvd-list は取得済みだが数値には未使用。
microsoft-\* は3章では使っていないが、5章の検知で `vuls.microsoft.db` の材料として使う（そちらのスナップショットは `data/sources.tsv` 側で固定している）。

### 基準日

スナップショットの基準日は、NVDデータセット中の `lastModified` の最大値である **2026-07-29** とした。C4（付与遅延）の測定に使えるGit履歴の開始は、NVDが2025-06-26、VulnCheckが2025-08-06。

## 3章の集計をやり直す

```sh
cd data/analysis
python3 extract.py          # 全CVEのメタデータをCSVへ（約1分。他スクリプトの入力）
python3 agg3.py             # 3.2節（公開年別の付与率）、3.3節のCNA別、滞留日数
python3 extract2.py         # 3.3節（バージョン特定可能率、粒度）
python3 fortinet_c123.py    # 表1（Fortinet基準の C1〜C3）
python3 cisco_c14.py        # 3.4節 Cisco の C1
python3 c4.py 25            # 3.5節 全体（引数は標本の間引き幅）
python3 fortinet_c4.py      # 3.5節 Fortinet
python3 cisco_c4.py         # 3.5節 Cisco
```

各スクリプトの出力は同名の `.out` として commit してあるので、`diff` で照合できる。
データルートは各スクリプトの `BASE` で、リポジトリルート直下の `ghcr.io/vulsio/vuls-data-db` を指す（`__file__` からの相対で解決するのでclone先に依存しない）。

## 5章の検知結果をやり直す

DBもスキャン結果も commit してあるので、検知のやり直しだけで再現できる。

```sh
sh data/bin/unpack-db.sh        # commit 済みの .db.zst と vuls バイナリを展開
sh data/bin/detect.sh           # 4つのDBそれぞれで検知し直す
python3 data/analysis/detect_eval.py   # 表2 の集計
```

DBの作り直し、スキャン結果の内訳、vuls のビルド手順は [`data/README.md`](data/README.md) を参照。

## 実行環境

- Python 3.10.5（標準ライブラリのみ）
- git（`git log --name-only` と `git cat-file --batch` を使用）
- zstd（`data/bin/unpack-db.sh` が使用）
- LaTeX（原稿のビルド。`docs/GNUmakefile` は Docker イメージ `paperist/alpine-texlive-ja` を使う）
