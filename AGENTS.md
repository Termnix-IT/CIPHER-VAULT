# AGENTS.md

## 作業ルール

- 回答は原則日本語。コード・コマンド・API名は元の表記を維持する。
- 実行・importされるファイルは英語名、読むための文書は日本語名を優先する。既存の命名規則を優先する。
- 明示的な依頼なしに stage・commit・push・リリース公開を行わない。
- 依存追加、アーキテクチャ、外部API、保存方式、セキュリティの設計判断では、実装前に `implementation-researcher` を使用する。既存の調査は前提が同じなら再利用する。
- 文書や既存パターンに沿う小さな変更では調査を簡略化できるが、変更に必要な確認は省略しない。

## 構成と責務

npm workspaces、TypeScript、React + Vite、Node.js標準HTTP、Electron、better-sqlite3を使用する。

- `apps/web/src/lib/api.ts`: WebのHTTPとElectronのpreload APIを切り替える。
- `apps/web/src/App.tsx`: 保管庫状態、一覧・選択、自動ロックを管理する。
- `apps/api/src/routes/router.ts`: HTTP入口。入力検証はIPCからも呼ばれるサービス層で行う。
- `apps/api/src/services/vault-service.ts`: 初期設定、解除、ロック、リセット。
- `apps/api/src/services/crypto-service.ts`: 鍵導出、検証値、AES-256-GCM、メモリ上の鍵。
- `apps/api/src/services/vault-store.ts`: SQLiteの保管庫メタデータを読み書きする。
- `apps/api/src/services/entry-service.ts`: エントリCRUDと暗号処理の呼び出し。
- `apps/api/src/db/database.ts`: 実行時のスキーマ作成・移行。変更時は `schema.sql` も揃える。
- `apps/electron/src/main.ts` / `preload.ts`: ウィンドウ、IPC、サービス初期化、クリップボード。
- `apps/electron/src/manual-updater.ts` / `update-service.ts`: 手動更新の状態制御とElectron接続。
- `packages/shared/src/types.ts`: Web・API・Electronの共通型。契約変更はここから揃える。

WebはHTTP → サービス → SQLite、Electronはpreload → IPC → 同じサービス → SQLiteを使う。Electron版の保管庫操作にHTTPサーバーは不要。

## コマンド

リポジトリルートで実行する。Windows配布にはPowerShellとElectron用のネイティブ依存が必要。

| コマンド | 用途 |
|---|---|
| `npm install` | 依存導入 |
| `npm run dev` | Web（5173）+ API（3001） |
| `npm run dev:desktop` | Vite + Electron開発起動 |
| `npm run build` | Web + APIビルド |
| `npm run build:desktop` | Web + API + Electronビルド |
| `npm run start` | ビルド済みAPI起動 |
| `npm run start:desktop` | ビルド済みElectron起動 |
| `npm run test:updates` | 手動更新の制御テスト |
| `npm run test:api` | 一時DBでAPI・配布スクリプトの回帰テスト |
| `npm run package:desktop` | Windows setup / portable生成（公開しない） |
| `npm run package` | Node.jsで動かすWeb/API配布フォルダ生成 |

個別ビルドは `build:shared` / `build:web` / `build:api` / `build:electron`。API監視起動は `npm --workspace apps/api run dev:watch`。

## 検証とデータ保護

- コード変更は対象ビルドを実行する。共通型や両実行環境に影響する変更は `npm run build:desktop` で確認する。
- サービス・保存・HTTP・Web配布変更は `npm run test:api`、更新変更は `npm run test:updates` を実行する。
- `test:api` はElectronをNodeモードで使う。better-sqlite3はNodeとElectronでABIが異なるため、ネイティブモジュールの不一致をコード不具合と混同しない。
- UI変更は影響する操作を確認し、ビルド成功と画面確認を区別して報告する。
- テストは一時DBを使う。利用中の `userData`、`apps/api/data`、既存の `release/data` を初期化・上書きしない。
- Web/APIの保存先は `PASSWORD_MANAGER_DATA_DIR` で指定可能。Electronは `app.getPath("userData")/data` を設定してからサービスを読み込む。
- 配布物に開発用DBを含めない。`release/data` に既存データがあればWeb配布スクリプトは停止する。
- DB、ジャーナル、個人情報、検証用ログをコミットしない。内部資料は `docs/private/`（README以外はGit対象外）。
- パスワード・メモを暗号化し、一覧には含めない。サービス名・ログインID・URL・タグ・グループは平文であることを保持する。
- 鍵・検証値やDB形式の変更では旧DBの解除、誤パスワード、既存暗号文の復号を検証し、移行・旧版互換性の制約を文書化する。

## 更新・配布の維持事項

- バージョンはルート `package.json` を基準とする。公開時はlockfile・リリースノート・タグ・成果物の版を揃える。
- 更新確認・ダウンロード・適用はユーザー操作で行う。起動時確認や通常終了時の自動適用を追加しない。
- setup向けの更新適用前に保管庫をロックする。portable・開発モードは配布ページへ案内する。
- 原本 `build/icon.png` から `scripts/build-icons.ps1` で `build/icon.ico` とWeb用画像を生成する。
- Windows標準アイコンへの退行を防ぐため `signAndEditExecutable: true` を維持する。
- 公開手順と必要な更新用成果物は [リリース手順](docs/リリース手順.md) を参照する。生成済みexeは再ビルドするまでソース修正を含まない。

詳細は [設計](docs/設計.md)、[開発・配布手順](docs/開発・配布手順.md)、[手動更新とアイコン](docs/手動更新とアイコン.md) を参照する。
