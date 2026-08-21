# css2026-data

CSS2026 OWSトラック投稿論文「脆弱性検知条件の供給源の再検討 ——検知精度によるNVD・VulnCheck・一次データソースの比較とLLMによる構造化——」の原稿と、本文の数値を算出した測定スクリプト。

| | |
|---|---|
| [`docs/`](docs/) | 原稿。`css.tex` が本体、`css.pdf` が提出版（本文8ページ、参考文献含む） |
| [`data/analysis/`](data/analysis/) | 本文の数値を算出したスクリプトと、その出力（`*.out`） |
| [`data/bin/`](data/bin/) | 5章の検知実験を回すスクリプト |
| [`data/sources.tsv`](data/sources.tsv) | 5章の各DBが、どのアーティファクトのどのcommitから作られたかの記録 |

原稿のビルド:

```sh
cd docs && latexmk css.tex
# もしくは make run（Docker イメージ paperist/alpine-texlive-ja を使う）
```

論文の章立てと成果物の対応は次のとおり。

| 章 | 内容 | 対応する成果物 |
|---|---|---|
| 3 | 検知条件の供給実態の定量調査 | `data/analysis/agg3.py` `extract2.py` `fortinet_c123.py` `cisco_c14.py` `c4.py` `stability.py` |
| 4 | 一次データソースの構造化（LLMの3パターン） | vuls-data-update の各PR（原稿の参考文献を参照） |
| 5 | 検知精度への影響の評価 | `data/bin/` の検知スクリプトと `data/analysis/detect_eval.py` `paper_numbers.py` |

## 測定データは含めていない

次のものは容量が大きいため commit していない。

| | 置き場所 | 大きさ |
|---|---|---|
| 収集した脆弱性情報（raw / extracted） | `ghcr.io/vulsio/vuls-data-db/` | 数GB |
| 5章の検知に使った vuls DB | `data/db/vuls.*.db.zst` | 183MB |
| 5章のスキャン結果 兼 検知結果 | `data/<vendor>/results/<slot>/*.json` | 170MB |
| 検知に使った vuls v1 のバイナリ | `data/vuls.zst` | 20MB |

このうち下3つは commit `254e523` までは含まれていたので、必要なら取り出せる。

```sh
git checkout 254e523 -- data/db data/vuls.zst \
    data/apple data/cisco data/fortinet data/microsoft data/openssh
```

**Microsoft の slot 00（`data/microsoft/results/*T00-00-00+0900/`）だけは実機 Windows の
スキャン結果で、実機を用意しない限り取り直せない。** 他は後述の手順で再生成できる。

各スクリプトの出力は同名の `.out` として commit してあるので、データを取り直さなくても
本文の数値がどう算出されたかは追える。

## 3章の集計に用いたスナップショット

論文3章の数値はすべて下記から算出している。**再検証にはこのcommit hashを指定して取得すること。**

- 取得先: `ghcr.io/vulsio/vuls-data-db`（各行の source がOCIアーティファクトのタグ名）
- 配置先: `ghcr.io/vulsio/vuls-data-db/<source>/`（Zstandardで展開すると `.git/` のみの
  ディレクトリになるので、`git -C <dir> checkout <commit>` で任意時点に復元できる）
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

この表は `sh data/analysis/dataset-manifest.sh` で再生成・照合できる。

3章の数値に直接使っているのは次の5つで、mitre-cve-v5 と enisa-euvd-list は取得済みだが未使用。
microsoft-\* は3章では使わず、5章の `vuls.microsoft.db` の材料になる（そちらは `data/sources.tsv` 側で固定）。

| source | 用いた箇所 |
|---|---|
| vuls-data-raw-nvd-feed-cve-v2 | 3.2節・3.3節、3.4節と3.5節の比較対象、C4のGit履歴 |
| vuls-data-raw-vulncheck-nist-nvd2 | 同上 |
| vuls-data-raw-fortinet-cvrf / -csaf | 3.4節・3.5節（一次データソースの基準） |
| vuls-data-raw-cisco-json | 3.4節のC1、3.5節のC4 |

スナップショットの基準日は、NVDデータセット中の `lastModified` の最大値である **2026-07-29**。
C4（付与遅延）に使えるGit履歴の開始は、NVDが2025-06-26、VulnCheckが2025-08-06。

## 3章の集計をやり直す

上の表のとおりデータを `ghcr.io/vulsio/vuls-data-db/` へ配置してから実行する。

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
python3 stability.py        # 3.5節 安定性（VulnCheckのGit履歴を辿る）
```

データルートは各スクリプトの `BASE`（リポジトリルート直下の `ghcr.io/vulsio/vuls-data-db`）で、
`VULS_DATA_ROOT` で上書きできる。出力は同名の `.out` と `diff` で照合できる。

`paper_numbers.py` は他の `.out` が扱っていない数値（3.3節のWindows、5.2節(2)(4)(6)、
5.4節のApple欠落）をまとめて再計算する。検知結果も要るので、下記のDBとスキャン結果を
用意してから実行すること。

## 5章の検知をやり直す

同じスキャン結果を4つ複製し、DBだけを変えて検知させている。

| slot | 結果ディレクトリ | 使うDB | 中身 |
|---|---|---|---|
| 00 | `<vendor>/results/2026-08-01T00-00-00+0900/` | `db/vuls.<vendor>.db` | 一次データソース |
| 01 | `…T00-00-01+0900/` | `db/vuls.nvd.db` | NVD |
| 02 | `…T00-00-02+0900/` | `db/vuls.vulncheck.db` | VulnCheck NVD++ |
| 03 | `…T00-00-03+0900/` | `db/vuls.nvd-vulncheck.db` | NVD + VulnCheck |

ディレクトリ名の日時に意味はない。vuls v1 の `report` が結果ディレクトリを日時で選ぶため、
同じスキャン結果を4つに複製して別々のDBで検知させるための連番である。
`scannedCves` 以外は4つとも同一なので、差分はすべてDBの違いに由来する。

```sh
sh data/bin/unpack-db.sh          # .db.zst と vuls.zst を展開（上記のとおり要復元）
sh data/bin/detect.sh             # 4 slot ぶん検知し直す（ベンダ指定は引数で）
python3 data/analysis/detect_eval.py   # 表2の集計
```

### slot 02 と slot 03 は足し算にならない

vuls は CPE のデータソースを2つに分けており、VulnCheck NVD++（とJVN）は「信頼度の低い」側に
置かれている（`detector/vuls2/vuls2.go` の `verifiedCPESources` / `isSuppressedCPESource`）。
あるCVEについて verified 側（NVD、Fortinet、Cisco、PaloAlto、Apple）が
`part:vendor:product` を**定義してさえいれば**、たとえそのバージョン範囲がスキャン対象に
一致せず非検知でも、VulnCheck 側の同じ製品の検知は捨てられる。

- slot 02 はDBに verified ソースが1つも入っていないので抑制が働かない。
  **VulnCheckのデータそのものが持つ検知力**を測っている。
- slot 03 はNVDが verified 側として抑制をかける。
  **NVD+VulnCheckを積んだvulsの実際の挙動**であり、slot 01 と slot 02 の和集合ではない。

論文5.1節・5.2節(5)がこの規則を扱っている。

### DBを作り直す

`data/sources.tsv` の tag / commit を指定して取得・投入する。必要なツールは
`vuls-data-update`（`nightly` の `a1fb26a2`。Apple #917/#939/#940、OpenSSH #928、
Fortinet補完表 #941 がすべて入っている）と `vuls2`
（`663ae1050b94a610d00c569a3dab1503a07e8a65`）。

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

# 3. DBごとに、sources.tsv の上の行から順に投入して圧縮する
vuls db init     --dbpath data/db/vuls.<name>.db
vuls db add      --dbpath data/db/vuls.<name>.db data/db/ghcr.io/vulsio/vuls-data-db/<extracted tag>
vuls db compress --dbpath data/db/vuls.<name>.db
```

`ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-apple-security-releases` は空の
プレースホルダなので apple は raw から extract する。fortinet-cvrf も raw から取る
（従来ここで固定していた extracted の commit `b915804` は #941 の補完表の作り直しより
前のもので、5章の数値は作り直したあとの抽出器で算出しているため）。
OpenSSH は raw の `raw/` をモデルによる変換で作る構成のため fetch だけでは再生成できない
（vuls-data-update の PR #928 を参照）。

### 検知に使う vuls

Apple と OpenSSH の検知に必要なPRはすべて上流にマージされている。

| リポジトリ | commit | 含まれるPR |
|---|---|---|
| MaineK00n/vuls-data-update | `a1fb26a2`（nightly） | #917 / #939 / #940 / #928 / #941 |
| future-architect/vuls | `386ec577`（master） | #2635 / #2636 |

```sh
git -C vuls switch --detach 386ec57759dd
CGO_ENABLED=0 GOEXPERIMENT=jsonv2 go build -trimpath -ldflags "-s -w" -o vuls ./cmd/vuls
```

## 実行環境

- Python 3.10.5（標準ライブラリのみ）
- git（`git log --name-only` と `git cat-file --batch` を使用）
- zstd（`data/bin/unpack-db.sh` が使用）
- LaTeX（原稿のビルド。`docs/GNUmakefile` は Docker イメージ `paperist/alpine-texlive-ja` を使う）
