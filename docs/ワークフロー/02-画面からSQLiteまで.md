# 2. 画面からSQLiteまで

画面は `window.passwordManager` からTauriのコマンドを呼び、Rustの中核が保管庫を扱います。図のDB名は従来形式です。新形式は[通常起動とv2サービス](../設計.md#通常起動とv2サービス)を参照してください。

```mermaid
flowchart LR
    user([ユーザー]) --> ui[React UI<br/>App / LockScreen / VaultDashboard]
    ui --> client[lib/api.ts]
    client --> bridge[window.passwordManager<br/>desktop-api.js]
    bridge --> ipc[Tauri IPC<br/>許可したコマンドだけ]

    subgraph desktop[apps/desktop]
        ipc --> commands[コマンドの入口<br/>セッションの世代とロックを確認]
        commands --> clipboard[期限付きクリップボード]
        osEvents[画面ロック・スリープの通知] --> commands
    end

    subgraph core[crates/vault-core]
        commands --> services{要求の種類}
        services --> vault[保管庫<br/>vault.rs / session.rs]
        services --> entries[エントリ<br/>vault.rs / legacy.rs]
        services --> password[パスワード生成<br/>password.rs]
        vault --> crypto[暗号<br/>crypto.rs]
        entries --> crypto
    end

    vault --> sqlite[(SQLite<br/>vault_metadata)]
    entries --> sqliteEntries[(SQLite<br/>password_entries)]
    crypto --> memory[(メモリ上の保管庫鍵)]

    sqlite --> response[処理結果]
    sqliteEntries --> response
    password --> response
    response -->|コマンドの戻り値| ui
```

## 境界と責務

`lib/api.ts` は `window.passwordManager` を呼ぶだけで、保管庫の処理を持ちません。デスクトップ（`apps/desktop`）がコマンドの入口でセッションの世代とロック・OS状態を確認し、中核（`crates/vault-core`）が入力検証・ロック判定・暗号・DB操作を担当します。画面が使う共通型は `packages/shared/src/types.ts` です。DBは起動時に形式を検査して開き、終了時にロックして閉じます。

具体的な境界は[画面とCSP](../設計.md#画面とcsp)、[画面から呼べるコマンド](../設計.md#画面から呼べるコマンド)、[入力検証](../設計.md#入力の検証と上限)、[DBの接続](../設計.md#dbの接続と形式判定)を参照してください。
