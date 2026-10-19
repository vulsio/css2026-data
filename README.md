# css2026-data

CSS2026 OWSトラック投稿論文「脆弱性検知条件の供給源の再検討 ——検知精度によるNVD・VulnCheck・一次データソースの比較とLLMによる構造化——」の原稿と発表スライド。

| | |
|---|---|
| [`docs/css.tex`](docs/css.tex) | 原稿の本体。各章は `docs/<番号>-<章名>/` 以下 |
| [`docs/css.pdf`](docs/css.pdf) | 提出版（本文8ページ、参考文献含む） |
| `docs/slides.pdf` | 発表スライド（15分発表） |
| [`docs/refs.bib`](docs/refs.bib) | 参考文献 |

## 原稿のビルド

```sh
cd docs && latexmk css.tex
```

Docker を使う場合は `docs/GNUmakefile` の `make run` で、イメージ `paperist/alpine-texlive-ja` の中で `latexmk -pvc` を動かす（`make stop` で止める）。

## 引用

本稿の前稿を本文で引用しているのと同じ体裁（`docs/refs.bib` の `nakaoka2025`）に揃えてある。

```bibtex
@inproceedings{nakaoka2026,
  author       = {中岡 典弘 and 篠原 俊一},
  title        = {脆弱性検知条件の供給源の再検討 ---検知精度によるNVD・VulnCheck・一次データソースの比較とLLMによる構造化---},
  booktitle    = {コンピュータセキュリティシンポジウム2026 (CSS2026) 論文集},
  year         = {2026}
}
```

英語で引くなら title を次に差し替える。

> Revisiting the Supply of Vulnerability Detection Conditions:
> Comparing NVD, VulnCheck and Primary Sources by Detection Accuracy, with LLM-assisted Structuring

ページ番号は論文集の発行後に `pages` を足すこと。前稿は次のとおり。

```bibtex
@inproceedings{nakaoka2025,
  author       = {中岡 典弘 and 篠原 俊一},
  title        = {広範な脆弱性情報の統合管理と履歴追跡},
  booktitle    = {コンピュータセキュリティシンポジウム2025 (CSS2025) 論文集},
  year         = {2025}
}
```
