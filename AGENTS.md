# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## 開発コマンド

```bash
# 初回セットアップ
npm install

# 開発サーバー起動（Web + API 同時）
npm run dev

# 個別起動
npm run dev:web        # フロントエンド (Vite, port 5173)
npm run dev:api        # API (ビルド→実行, port 3001)
npm --workspace apps/api run dev:watch  # API ホットリロード

# ビルド
npm run build          # Web + API 両方
npm run build:web
npm run build:api

# 本番起動
npm run start          # ビルド済み API を起動

# リリースパッケージ作成
npm run package        # ビルド → scripts/package-release.ps1 実行
```

## アーキテクチャ

npm ワークスペース構成のモノレポ：

- `apps/api/` — Node.js ネイティブ HTTP サーバー (TypeScript、port 3001)
- `apps/web/` — React 18 + Vite フロントエンド (port 5173)
- `packages/shared/` — 両アプリ共通の TypeScript 型定義

### データフロー

```
React (5173) → HTTP/JSON → Node.js API (3001) → SQLite (apps/api/data/)
```

開発時は Vite のプロキシ設定 (`vite.config.ts`) により `/vault`, `/entries`, `/password` へのリクエストが port 3001 へ転送される。

### API サービス層 (`apps/api/src/services/`)

| ファイル | 役割 |
|---------|------|
| `vault-service.ts` | 保管庫の初期化・ロック解除・ロック。復号鍵をメモリ保持 |
| `crypto-service.ts` | AES-256-GCM 暗号化/復号、Scrypt KDF によるパスワード導出 |
| `entry-service.ts` | パスワードエントリの CRUD、暗号化/復号を crypto-service に委譲 |
| `password-service.ts` | パスワード生成ロジック |
| `vault-store.ts` | アクティブな vault key のメモリ管理 |

### セキュリティ設計

- マスターパスワードは保存しない。Scrypt KDF で導出した検証器のみ SQLite に保存
- エントリのパスワードとメモは AES-256-GCM で暗号化（12byte IV + 16byte 認証タグ）
- 復号鍵はメモリのみに保持し、5分無操作でロック時にクリア
- パスワード比較は `timingSafeEqual` でタイミング攻撃を防ぐ

### 共通型定義 (`packages/shared/src/types.ts`)

`PasswordEntry`, `VaultStatus`, `VaultSetupPayload` など全型定義の一元管理場所。API・Web 双方でインポートして使う。

### フロントエンド画面遷移

```
起動 → GET /vault/status
  ├─ 未設定 → LockScreen (初期設定モード)
  ├─ ロック中 → LockScreen (ロック解除モード)
  └─ 解除済 → VaultDashboard (エントリ一覧・管理)
```

### データベーススキーマ (`apps/api/src/db/schema.sql`)

- `vault_metadata` — マスターパスワード検証情報 (行は常に1件)
- `password_entries` — 暗号化済みのパスワードエントリ (UUID主キー)
