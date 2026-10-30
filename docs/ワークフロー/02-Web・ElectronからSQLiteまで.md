# 2. Web・ElectronからSQLiteまで

WebはHTTP、ElectronはIPCを経由し、同じサービス層を使います。図のDB名は従来形式です。新形式は[通常起動とv2サービス](../設計.md#通常起動とv2サービス)を参照してください。

```mermaid
flowchart LR
    user([ユーザー]) --> ui[React UI<br/>App / LockScreen / VaultDashboard]
    ui --> client[lib/api.ts]
    client --> transport{window.passwordManager<br/>が存在するか}

    subgraph webPath[Web版]
        transport -- いいえ --> fetch[Fetch API]
        fetch --> vite[Vite開発プロキシ<br/>本番時はNode HTTPサーバー]
        vite --> router[HTTP Router]
    end

    subgraph electronPath[Electron版]
        transport -- はい --> bridge[preload<br/>contextBridge]
        bridge --> ipc[ipcRenderer.invoke]
        ipc --> handlers[Electron Main<br/>ipcMain handlers]
    end

    router --> services
    handlers --> services

    subgraph common[共通サービス層]
        services{要求の種類}
        services --> vault[Vault Service]
        services --> entries[Entry Service]
        services --> password[Password Service]
        vault --> crypto[Crypto Service]
        entries --> crypto
        vault --> metadata[Vault Store]
    end

    metadata --> sqlite[(SQLite<br/>vault_metadata)]
    entries --> sqliteEntries[(SQLite<br/>password_entries)]
    password --> response[生成結果]
    sqlite --> response[処理結果]
    sqliteEntries --> response
    crypto --> memory[(メモリ上の保管庫鍵)]

    response --> returnPath{呼び出し元}
    returnPath -->|HTTP JSON| ui
    returnPath -->|IPC Promise| ui

    ui --> copyClient[コピー要求]
    copyClient --> copyMode{実行環境}
    copyMode -->|Web| browserClipboard[Navigator Clipboard API]
    copyMode -->|Electron| electronClipboard[Electron clipboard]
```

## 実行経路の違い

| 項目 | Web版 | Electron版 |
|---|---|---|
| 通信 | HTTP/JSON | preload経由のIPC |
| 入口 | `apps/api/src/routes/router.ts` | `apps/electron/src/desktop-main.ts` のIPC handler |
| サービス層 | APIサービスを使用 | 同じAPIサービスを直接import |
| 開発時の画面 | Vite `http://localhost:5173` | Viteを検出して読み込み |
| 配布時の画面 | APIが静的ファイルを配信 | `apps/web/dist/index.html` を読み込み |
| DB保存先 | 通常は `apps/api/data` | Electron `userData/data` |

## 境界と責務

`lib/api.ts` がHTTPとIPCを切り替え、共通サービスが入力検証・ロック判定・暗号・DB操作を担当します。共通型は `packages/shared/src/types.ts` です。DBは起動時に形式を検査して開き、終了時にロックして閉じます。

具体的な境界は[画面のsandboxとCSP](../設計.md#画面のsandboxとcsp)、[入力検証](../設計.md#入力の検証と上限)、[DBの接続](../設計.md#dbの接続と形式判定)を参照してください。
