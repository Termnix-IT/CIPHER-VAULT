# GitHub リリース手順

## 目的

この手順書は、`CIPHER VAULT` のデスクトップ版を `GitHub Releases` で公開するときの標準フローをまとめたものです。

対象:

- Windows 向け `setup` 配布物を公開する
- 必要に応じて `portable` 版も併記する
- GitHub の自動生成リリースノートを使いつつ、利用者向けの説明を手動で補う

---

## 事前確認

作業ディレクトリ:

```powershell
cd "C:\Users\lugep\デスクトップ\Google Drive\ProjectFolder\PasswordManeger"
```

確認項目:

- `package.json` の `version` を今回の公開版に合わせる
- ローカルで `npm run build:desktop` が通る
- 必要なら `npm run dev:desktop` で見た目と動作を確認する
- 公開対象の変更をコミット済み、または公開内容が明確である

---

## 配布物を作る

まず Windows 向け成果物を生成します。

```powershell
npm run package:desktop
```

主な出力先:

```text
dist-desktop/
```

主な成果物:

- `CIPHER VAULT-<version>-x64-setup.exe`
- `CIPHER VAULT-<version>-x64-portable.exe`
- `latest.yml`
- `*.blockmap`

通常公開では `setup.exe` を主導線にし、`portable.exe` は補助的な選択肢として添付します。

---

## GitHub Releases で公開する

対象リポジトリ:

- [Termnix-IT/PasswordManeger](https://github.com/Termnix-IT/PasswordManeger)

手順:

1. GitHub の `Releases` 画面を開く
2. `Draft a new release` を選ぶ
3. Tag に `v<version>` を入力する
4. 初回作成なら対象ブランチを選ぶ
5. Title に `CIPHER VAULT v<version>` を入力する
6. `Generate release notes` を押す
7. 自動生成された本文の先頭に、利用者向けの要約を追記する
8. `dist-desktop/` から配布物をアップロードする
9. ベータ版なら `This is a pre-release` を付ける
10. 問題なければ `Publish release` を押す

公開時に添付する優先順位:

- 1番目: `setup.exe`
- 2番目: `portable.exe`
- 3番目: `latest.yml`
- 4番目: `blockmap`

`latest.yml` と `blockmap` は将来の自動更新対応や差分配布を見据えるなら一緒に付けておく方が整合が取れます。

---

## リリースノートの書き方

GitHub の自動生成ノートは、変更一覧の収集には便利ですが、利用者向けには説明不足になりやすいです。
そのため、本文の冒頭だけは手動で書く運用を推奨します。

基本構成:

```md
## CIPHER VAULT v<version>

このリリースの概要を 2 - 3 行で説明

### 追加
- 利用者に見える新機能

### 改善
- 操作性や安定性の改善

### 修正
- 不具合修正

### 配布物
- `setup.exe`: 通常利用向け
- `portable.exe`: インストール不要

### 注意
- 既知の制約や保存先、アップデート時の注意
```

ポイント:

- 実装の内部事情ではなく、利用者が何を得るかを書く
- 冒頭 3 行で「何の更新か」を伝える
- `setup` と `portable` の違いを毎回簡潔に書く
- 初回リリースでは「既存版からの更新ではない」ことも明記する

---

## ラベル運用

GitHub の自動生成リリースノートは `.github/release.yml` を参照して分類されます。

推奨ラベル:

- `feature`
- `enhancement`
- `desktop`
- `fix`
- `bug`
- `docs`
- `refactor`
- `build`
- `ci`
- `skip-release-notes`

`skip-release-notes` を付けた変更は、公開ノートに載せたくない内部修正の除外用です。

---

## 初回リリースの目安

このリポジトリの初回デスクトップ公開は、現状の `package.json` に合わせて `v0.1.0` が自然です。

公開時の例:

- Tag: `v0.1.0`
- Title: `CIPHER VAULT v0.1.0`

---

## 関連ファイル

- [package.json](C:/Users/lugep/デスクトップ/Google%20Drive/ProjectFolder/PasswordManeger/package.json:1)
- [docs/デスクトップ起動・配布手順書.md](C:/Users/lugep/デスクトップ/Google%20Drive/ProjectFolder/PasswordManeger/docs/デスクトップ起動・配布手順書.md:1)
- [.github/release.yml](C:/Users/lugep/デスクトップ/Google%20Drive/ProjectFolder/PasswordManeger/.github/release.yml:1)
- [docs/release-notes/v0.1.0.md](C:/Users/lugep/デスクトップ/Google%20Drive/ProjectFolder/PasswordManeger/docs/release-notes/v0.1.0.md:1)
