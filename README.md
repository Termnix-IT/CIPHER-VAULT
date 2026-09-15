# CIPHER VAULT

ローカル動作のパスワード管理アプリです。保管庫データは自端末の SQLite に保存され、外部へ送信しません。手動の更新確認・ダウンロード時には GitHub に接続します。Web 画面では Google Fonts の読み込みも行います。

---

## 機能

- **保管庫の初期設定・解錠・ロック** — マスターキー（パスフレーズ）で保管庫を管理
- **エントリの CRUD** — サービス名・ログインID・パスワード・URL・タグ・メモを管理
- **パスワード生成** — 大文字・小文字・数字・記号を組み合わせた安全なパスワードを生成
- **クリップボードコピー** — ログインID・パスワードをワンクリックでコピー
- **自動ロック** — 5 分間操作がなければ保管庫を自動ロック
- **保管庫の完全リセット** — マスターキーを忘れた場合に、確認操作を経て保存データを消去し再設定
- **検索** — サービス名・ログインID・タグで絞り込み
- **手動アップデート** — Windows の setup 版では「アプリ情報」から確認・ダウンロード・再起動して更新。起動時の確認や通常終了時の自動適用は行いません

更新機能の使い方と配布条件は [手動更新とアイコン](docs/手動更新とアイコン.md) を参照してください。
更新機能のない旧版からは、アプリを終了して新しい setup を同じインストール先へ上書きします。2026-09-15 に利用者による移行完了を確認しています。

---

## 動作環境

| 要件 | バージョン |
|---|---|
| Node.js | 20 以上 |
| npm | 10 前後 |
| OS | Windows / macOS / Linux |

---

## セットアップ

```bash
# 依存パッケージのインストール
npm install
```

---

## 起動

### 開発モード（推奨）

```bash
npm run dev
```

Web（フロントエンド）と API を同時に起動します。

| サービス | URL |
|---|---|
| Web | http://localhost:5173 |
| API | http://localhost:3001 |

> フロントエンドはファイル保存ごとに自動反映されます。
> API のコードを変更した場合は `Ctrl+C` で停止後、再度 `npm run dev` を実行してください。

### API のみホットリロード

```bash
npm --workspace apps/api run dev:watch
```

### 個別起動

```bash
npm run dev:web   # フロントエンドのみ
npm run dev:api   # API のみ（ビルド→実行）
```

### Electron デスクトップ起動

```bash
# 事前に一度だけ Electron 依存をインストール
npm install

# Electron + Vite で起動
npm run dev:desktop
```

Electron 版は `preload + IPC` 経由でローカル処理へ直接接続します。
開発時は `apps/api/dist` を参照するため、`dev:desktop` / `build:desktop` を使ってください。

---

## ビルド・配布

```bash
# ビルド（Web + API）
npm run build

# ビルド済み API を起動
npm run start
# → http://localhost:3001 を開く

# Electron 向けビルド
npm run build:desktop

# ビルド済み Electron を起動
npm run start:desktop

# Windows 向けインストーラー / portable を作成
npm run package:desktop

# 配布用パッケージを作成
npm run package
# → release/ フォルダが生成される
```

`release/` フォルダを丸ごと渡し、受け取り側は `start.bat` を実行します。
初回起動時に必要なランタイム依存を自動インストールします。

`npm run package:desktop` を実行すると `dist-desktop/` に Windows 用の `NSIS installer` と `portable exe` が出力されます。
成果物名は `-setup` と `-portable` で分かれます。
配布用アイコンは `build/icon.ico` を参照します。
実行中ウィンドウのアイコンは `build/icon.png` を参照します。

### `setup` と `portable` の違い

- `setup` はインストーラー版です。通常利用のユーザー向けで、ショートカット作成やインストール先管理がしやすいです。
- `portable` はインストール不要の実行版です。すぐ試したい場合や、インストールしにくい環境で便利です。
- このアプリでは、どちらもデータ保存先は Electron の `userData` 配下です。`portable` でも exe の横に DB を置く方式ではありません。

### 配布方法

- OSS として公開する場合、`setup` と `portable` を `GitHub Releases` や公開ダウンロードページに載せて配布する形で問題ありません。
- 一般ユーザー向けには `setup` を主導線にし、`portable` は補助的な選択肢として併記するのが分かりやすいです。

---

## ディレクトリ構成

```text
CIPHER-VAULT/
├── .github/          # GitHub Releases の設定
├── apps/
│   ├── api/          # Node.js ローカル API（ポート 3001）
│   │   └── src/
│   │       ├── db/           # SQLite 接続・スキーマ
│   │       ├── lib/          # エラー処理・JSON・静的ファイル配信
│   │       ├── routes/       # HTTP ルーティング
│   │       ├── services/     # ビジネスロジック（暗号化・エントリ管理等）
│   │       └── server.ts     # エントリーポイント
│   ├── electron/     # Electron メインプロセス
│   │   └── src/
│   │       └── main.ts
│   └── web/          # React フロントエンド（ポート 5173）
│       └── src/
│           ├── components/   # BinaryRain 等の共通コンポーネント
│           ├── lib/          # API クライアント・カスタムフック
│           ├── pages/        # LockScreen・VaultDashboard
│           └── styles.css    # グローバルスタイル
├── packages/
│   └── shared/       # 共通 TypeScript 型定義
├── build/            # デスクトップ配布用アイコン
├── docs/             # 公開・非公開ドキュメント
│   ├── README.md     # 文書索引と公開判断基準
│   ├── private/      # Git管理外のローカル文書
│   ├── リリースノート/
│   ├── ワークフロー/
│   ├── リリース手順.md
│   ├── 開発・配布手順.md
│   └── 設計.md
└── scripts/          # リリーススクリプト
```

---

## 開発メモ

- `packages/shared/src/types.ts` に型を追加した場合、Web・API 両方が参照するため両側でのビルド確認を推奨
- API は Node.js の標準 `http` モジュールのみ使用（フレームワークなし）
- Web/APIのDBは既定で `apps/api/data/`、Electron版は `userData/data/` に保存される
- API・保存・Web配布の回帰確認は `npm run test:api`、更新制御は `npm run test:updates` を実行する
- 保管庫検証値の変更と旧版互換性については [v0.2.1の修正](docs/リリースノート/v0.2.1.md) を参照する

文書の一覧と公開判断基準は [docs/README.md](docs/README.md) を参照してください。
Desktop起動とパッケージ化の詳細は [docs/開発・配布手順.md](docs/開発・配布手順.md) を参照してください。
