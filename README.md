# css2026-data

CSS2026 OWSトラック投稿論文「脆弱性検知条件の供給源の再検討」の原稿と、測定に用いたデータ・スクリプト。

- 原稿: [`paper/css2026-ows.md`](paper/css2026-ows.md)
- 測定スクリプト: [`paper/analysis/`](paper/analysis/)
- LaTeX一式: [`docs/`](docs/)

## 実験データのスナップショット

論文中の数値はすべて下記スナップショットから算出している。データ本体は `.gitignore` により本リポジトリには含めないため、**再検証にはこのcommit hashを指定して取得すること**。

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
sh paper/analysis/dataset-manifest.sh
```

### 論文中で実際に使用しているもの

| source | 用いた箇所 |
|---|---|
| vuls-data-raw-nvd-feed-cve-v2 | 4章全体、5章の比較対象、C4のGit履歴 |
| vuls-data-raw-vulncheck-nist-nvd2 | 4章全体、5章の比較対象、C4のGit履歴 |
| vuls-data-raw-fortinet-cvrf / -csaf | 5章 C1〜C4（一次データソースの基準） |
| vuls-data-raw-cisco-json | 5章 C1・C4 |

microsoft-\*、mitre-cve-v5、enisa-euvd-list は取得済みだが本稿の数値には未使用（Microsoftは今後の測定対象）。

### 使用していないデータ

`vuls-data-raw-fortinet`（FortiGuard PSIRTのHTMLを変換したもの）は**一次データソースの基準として採用していない**。FortinetのCVRF/CSAFの更新に追従できておらず、2018〜2023年公開分ではノードの51%でバージョンが空になる（実際のアドバイザリには記載がある。例: [FG-IR-20-036](https://www.fortiguard.com/psirt/FG-IR-20-036) は「FortiAnalyzer 6.4.0, 6.2.3 and below」と明記）。詳細は原稿5.2節および8章を参照。

## 基準日

スナップショットの基準日は、NVDデータセット中の `lastModified` の最大値である **2026-07-29** とした。C4（付与遅延）の測定に使えるGit履歴の開始は、NVDが2025-06-26、VulnCheckが2025-08-06。

## 実行環境

- Python 3.10.5（標準ライブラリのみ）
- git（`git log --name-only` と `git cat-file --batch` を使用）

## 再現手順

詳細は原稿の付録Aを参照。概略は次のとおり。

```sh
cd paper/analysis
python3 extract.py          # 全CVEのメタデータをCSVへ（約1分）
python3 agg3.py             # 表1・表2・表4、4.6節
python3 extract2.py         # 表3、表4のバージョン特定可能率
python3 fortinet_c123.py    # 表5（C1〜C3、CVRF/CSAF基準）
python3 cisco_c14.py        # 5.3節 Cisco の C1
python3 c4.py 25            # 表6 全体行
python3 fortinet_c4.py      # 表6 Fortinet行
python3 cisco_c4.py         # 表6 Cisco行
```

データルートは `paper/analysis/c123b.py` の `BASE` で定義している。
