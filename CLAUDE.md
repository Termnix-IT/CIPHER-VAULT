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

Windowsのデスクトップアプリで、Tauri 2 + Rust、React + Vite、SQLite（rusqlite）を使用する。v0.9.0でElectron版から切り替え、その後にElectron版（`apps/electron`）・Node.jsのサービス（`apps/api`）・Web/API版を削除した（必要ならタグ `v0.9.0` を参照する）。設計判断は [設計](docs/設計.md#rust版の設計判断) を正とする。

- `crates/vault-core/`: 中核（Tauri非依存）。暗号形式、保存、セッション、初期設定・解除・ロック、エントリ操作、パスワード生成、バックアップ、監査、新規作成・鍵更新・リセット・復旧。入力検証もここで行う。一覧のアイコンは各エントリの中に暗号化して置く（`icons.rs` は検査と、v1.0.1までの別ファイルの取り込み）。
- `apps/desktop/`: Tauriのデスクトップアプリ。画面に公開するコマンドは `build.rs` の一覧と `tauri.conf.json` の `capabilities` の両方に書く（タイトルバー用のTauri本体のウィンドウ操作は `capabilities` だけに個別に書く）。CSPは `packages/shared/src/renderer-policy.ts` と `tauri.conf.json` の `csp` を同じ文字列にする。クリップボード・画面ロックとスリープの連動・多重起動の防止・Electron版の起動中の拒否・署名付きの手動更新もここが受け持つ。setupは `windows/installer-hooks.nsh` でElectron版を削除する。
- `apps/desktop/src/desktop-api.js`: 画面の `window.passwordManager` を用意し、各メソッドをコマンドへ渡す。
- `apps/web/src/lib/api.ts`: `window.passwordManager` を呼ぶ。保管庫の処理は持たない。
- `apps/web/src/App.tsx`: 保管庫状態、一覧・選択、自動ロックの画面反映を管理する。
- `packages/shared/src/types.ts`: 画面の型。コマンドの引数・戻り値を変えるときは、ここと `desktop-api.js`・中核を揃える。

保存先はElectron版と同じ `%APPDATA%\CIPHER VAULT\data` で、`CIPHER_VAULT_DATA_DIR` で差し替える。手で動かすときは必ず試験用フォルダを指定する。

## コマンド

リポジトリルートで実行する。Node.js 22.12以上、Rust（stable）とMSVCのビルドツールが必要。

| コマンド | 用途 |
|---|---|
| `npm install` | 依存導入 |
| `npm run build:web` | 画面のビルド（`apps/web/dist-tauri`） |
| `npm run build:tauri` | 画面とアプリのreleaseビルド（配布しない） |
| `npm run package:tauri` | setup / portableを `dist-tauri/` に生成（公開しない） |
| `npm run test:rust` | 中核とデスクトップの試験（Cargo workspace） |
| `npm run test:web` | 画面のセッション処理・CSPの一致・同梱フォントの試験 |
| `npm run test:tauri-shell` | 画面・CSP・IPCと保管庫操作の実ウィンドウ検証 |
| `npm run test:tauri-update` | 2版のsetupで実際に更新して、再起動とデータの維持を確認 |
| `npm run test:dependencies` | npm依存の脆弱性監査 |

起動は `npm run build:web` の後に `CIPHER_VAULT_DATA_DIR` を試験用フォルダにして `cargo run -p cipher-vault`。手順は [開発・配布手順](docs/開発・配布手順.md#起動する) を参照する。

## 検証とデータ保護

- コード変更は対象ビルドを実行する。Rustの変更は `npm run test:rust` と `cargo clippy --workspace --all-targets -- -D warnings`、画面・共通型の変更は `npm run test:web` と `npm run test:tauri-shell` を実行する。
- 更新・配布の変更は `npm run test:tauri-update` と `npm run package:tauri` を実行する。
- `installer-hooks.nsh`（Electron版の削除）を変えたときは、タグ `v0.9.0` の作業ツリーに変更したフックを置いて `npm run test:tauri-migration` を実行し、移行を確かめる。
- UI変更は影響する操作を確認し、ビルド成功と画面確認を区別して報告する。実際の画面ロック・スリープ、貼り付け、Win+V、保存ダイアログは自動試験で確かめられないので、手で確認したかどうかを区別して報告する。
- テストは一時フォルダを使う。利用中の `%APPDATA%\CIPHER VAULT`、残っている `apps/api/data`・`release/data` を初期化・上書きしない。
- DB、ジャーナル、個人情報、検証用ログをコミットしない。内部資料は `docs/private/`（README以外はGit対象外）。
- パスワード・メモは一覧に含めない。
- 保管庫はv2形式だけを扱い、従来形式とv0.8.0のElectron版との互換はv1.1.0でやめた（[保管庫の形式の打ち切り](docs/設計.md#保管庫の形式の打ち切り)）。v2のentryに欄を足すときは `user_version` と `.cvault` の `version` を上げて旧版に拒否させ、既存の保管庫・バックアップの読み込み、誤パスワード、固定ベクトル（`tests/fixtures/crypto-compatibility.json`）を検証し、どの版で開けなくなるかを文書化する。

## 更新・配布の維持事項

- バージョンはルート `package.json` を基準とし、`tauri.conf.json` はそこから読む。公開時はlockfile・リリースノート・タグ・成果物の版を揃える。
- 更新確認・ダウンロード・適用はユーザー操作で行う。起動時確認や通常終了時の自動適用を追加しない。適用前に保管庫をロックする。portable・開発用のビルドは配布ページへ案内する。
- 更新の署名用の秘密鍵（`~/.tauri/cipher-vault.key`）とそのパスワードを読まない・出力しない。署名付きの配布物は公開する人が手元で作る。
- 毎回のリリースに、Electron版向けのv0.8.0の `latest.yml`・setup・`.blockmap` を添付する。識別子 `io.github.termnix-it.ciphervault` と保存先を変えない。
- 原本 `build/icon.png` から `scripts/build-icons.ps1` で `build/icon.ico` と画面用画像を生成する。
- 公開手順と添付ファイルは [リリース手順](docs/リリース手順.md) を参照する。生成済みexeは再ビルドするまでソース修正を含まない。

詳細は [設計](docs/設計.md)、[開発・配布手順](docs/開発・配布手順.md)、[手動更新とアイコン](docs/手動更新とアイコン.md) を参照する。
