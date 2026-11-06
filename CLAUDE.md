# CLAUDE.md

このファイルを、このリポジトリの作業ルール、構成、コマンド、検証方法の正とする。グローバル設定と矛盾する場合はこのファイルを優先する。構成・コマンド・検証手順を変更した場合は、このファイルと `docs/` の該当箇所を更新する。

## 作業ルール

- 回答は原則日本語。コード・コマンド・API名は元の表記を維持する。
- 実行・importされるファイルは英語名、読むための文書は日本語名を優先する。既存の命名規則を優先する。
- git操作はグローバル設定に従う。このリポジトリは個人リポジトリとして扱い、作業用ブランチを最新の `main` に揃えて検証してから、PRなしで `main` へfast-forwardしてpushする。
- リリース公開とタグ作成は、事前に確認してから行う。
- 依存追加、アーキテクチャ、外部API、保存方式、セキュリティの設計判断では、実装前に `implementation-researcher` を使用する。既存の調査は前提が同じなら再利用する。
- 文書や既存パターンに沿う小さな変更では調査を簡略化できるが、変更に必要な確認は省略しない。
- 保管庫を操作できるのは本人の画面操作だけとし、外部のアプリ・エージェント・ブラウザ拡張から呼べる入口を追加しない（[設計方針](docs/設計.md#設計方針)）。

## 構成と責務

npm workspaces、TypeScript、React + Vite、Node.js標準HTTP、Electron、better-sqlite3を使用する。Electron版とNode APIはTauri 2 + Rustへ段階的に置き換え中で、方針と制約は [設計](docs/設計.md#rust版への移行) を正とする。移行が終わるまではTypeScriptのサービス層を正解とし、Rust版は同じ結果とエラー文言を返す。

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
- `crates/vault-core/`: Rust版の中核（Tauri非依存）。暗号形式、保存、セッション、初期設定・解除・ロック・リセット、エントリ操作、パスワード生成、バックアップ、監査、移行・鍵更新・リセット・復旧。挙動はTypeScript版と `tests/rust-parity-engine.mjs` で比べる。
- `apps/desktop/`: Tauriのデスクトップアプリ。画面に公開するコマンドは `build.rs` の一覧と `tauri.conf.json` の `capabilities` の両方に書く。CSPは `renderer-policy.ts` の `tauri` モードと一致させる。クリップボード・画面ロックとスリープの連動・多重起動の防止・署名付きの手動更新もここが受け持つ。保存先はElectron版と同じ `%APPDATA%\CIPHER VAULT\data` で、`CIPHER_VAULT_DATA_DIR` で差し替える。手で動かすときは必ず試験用フォルダを指定する。setupは `windows/installer-hooks.nsh` でElectron版を削除する。

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
| `npm run test:rust` | Rust版（Cargo workspace）の試験 |
| `npm run test:rust-parity` | Rust版とTypeScriptサービスの差分試験（API再ビルドを含む） |
| `npm run test:tauri-shell` | Rust版の画面・CSP・IPCと保管庫操作の実ウィンドウ検証 |
| `npm run build:tauri` | Rust版のreleaseビルド（配布はまだしない） |
| `npm run package:tauri` | Rust版のsetup / portableを `dist-tauri/` に生成（公開しない） |
| `npm run test:tauri-update` | Rust版の2版のsetupで実際に更新して、再起動とデータの維持を確認 |
| `npm run test:tauri-migration` | 試験用の製品名で、Electron版のsetupからRust版への移行とportable版を確認 |

個別ビルドは `build:shared` / `build:web` / `build:api` / `build:electron`。API監視起動は `npm --workspace apps/api run dev:watch`。

`experiments/tauri-poc/` はRust移行を判断した試作で、配布しない。既定は読取専用で、`CIPHER_VAULT_POC_WRITE=1` のときだけ保管庫のコピーへ書き込む。暗号形式を変更したときは `npm run test:rust` も確認する。サービスや入力検証を変更したときはRust版も揃え、`npm run test:rust-parity` で差がないことを確認する。手順は [開発・配布手順](docs/開発・配布手順.md#変更に応じた検証) を参照する。

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
