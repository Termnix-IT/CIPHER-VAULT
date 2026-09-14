# 3. エントリCRUDと暗号化

エントリの作成・一覧取得・詳細取得・更新・削除における、ロック判定、暗号化・復号、SQLite操作の流れです。

```mermaid
flowchart TD
    request([エントリ操作]) --> operation{操作種別}
    operation -->|Create| create[新規作成]
    operation -->|Read list| list[一覧取得]
    operation -->|Read detail| detail[詳細取得]
    operation -->|Update| update[更新]
    operation -->|Delete| remove[削除]

    create --> lockCheck
    list --> lockCheck
    detail --> lockCheck
    update --> lockCheck
    remove --> lockCheck

    lockCheck{保管庫鍵が<br/>メモリに存在するか}
    lockCheck -- いいえ --> locked[423<br/>保管庫はロックされています]
    lockCheck -- はい --> dispatch{操作を続行}

    dispatch -->|Create| validateCreate[必須項目を検証]
    validateCreate --> validCreate{serviceName・loginId・<br/>passwordが有効か}
    validCreate -- いいえ --> badRequest[400 入力エラー]
    validCreate -- はい --> encryptCreate[passwordとnotesを<br/>AES-256-GCMで暗号化]
    encryptCreate --> insert[(暗号化済みデータをINSERT)]
    insert --> readCreated[作成した行を再取得]
    readCreated --> decryptCreated[passwordとnotesを復号]
    decryptCreated --> createdResponse[作成済みエントリを返す]

    dispatch -->|Read list| selectList[(全行を更新日時の降順でSELECT)]
    selectList --> summaries[秘密情報を除いたSummaryへ変換]
    summaries --> listResponse[一覧を返す]

    dispatch -->|Read detail| selectDetail[(IDで1行をSELECT)]
    selectDetail --> foundDetail{存在するか}
    foundDetail -- いいえ --> notFound[404 エントリなし]
    foundDetail -- はい --> decryptDetail[passwordとnotesを<br/>AES-256-GCMで復号]
    decryptDetail --> detailResponse[完全なエントリを返す]

    dispatch -->|Update| validateUpdate[必須項目を検証]
    validateUpdate --> existsUpdate{対象が存在するか}
    existsUpdate -- いいえ --> notFound
    existsUpdate -- はい --> encryptUpdate[passwordとnotesを<br/>新しいIVで再暗号化]
    encryptUpdate --> updateRow[(対象行をUPDATE)]
    updateRow --> readUpdated[更新した行を再取得]
    readUpdated --> decryptUpdated[passwordとnotesを復号]
    decryptUpdated --> updatedResponse[更新済みエントリを返す]

    dispatch -->|Delete| deleteRow[(IDでDELETE)]
    deleteRow --> deleted{削除件数が1件以上か}
    deleted -- いいえ --> notFound
    deleted -- はい --> deleteResponse[success: trueを返す]
```

## 保存データの暗号化範囲

```mermaid
flowchart LR
    master[マスターパスワード] -->|Scrypt + Salt| key[32 byte 保管庫鍵]
    key --> memory[(プロセスメモリのみ)]

    password[password 平文] --> encryptPassword[AES-256-GCM]
    notes[notes 平文] --> encryptNotes[AES-256-GCM]
    memory --> encryptPassword
    memory --> encryptNotes

    encryptPassword --> passwordPayload[Base64<br/>12 byte IV + 16 byte Auth Tag + 暗号文]
    encryptNotes --> notesPayload[Base64<br/>12 byte IV + 16 byte Auth Tag + 暗号文]
    passwordPayload --> encryptedPassword[(encrypted_password)]
    notesPayload --> encryptedNotes[(encrypted_notes)]

    plainFields[service_name / login_id / url /<br/>tags / group_name / timestamps] --> plainColumns[(平文カラム)]
```

## 操作別の入出力

| 操作 | SQLite操作 | 暗号処理 | 返却内容 |
|---|---|---|---|
| Create | `INSERT`後に対象行を再取得 | password・notesを暗号化し、返却時に復号 | 完全なエントリ |
| Read list | 全件`SELECT` | 復号しない | ID、サービス名、ログインID、タグ、グループ、更新日時 |
| Read detail | ID指定`SELECT` | password・notesを復号 | 完全なエントリ |
| Update | 存在確認後に`UPDATE`、対象行を再取得 | password・notesを再暗号化し、返却時に復号 | 完全なエントリ |
| Delete | ID指定`DELETE` | なし | `{ success: true }` |

## セキュリティ境界

- すべてのCRUD操作は最初に、メモリ上に保管庫鍵が存在することを確認します。
- passwordとnotesだけが暗号化対象です。サービス名、ログインID、URL、タグ、グループ、日時は平文で保存されます。
- 暗号化のたびに12 byteのランダムIVを生成し、16 byteの認証タグと暗号文を連結してBase64化します。
- 一覧取得では暗号化済みpassword・notesを読み出しても復号・返却しません。
- 保管庫をロックするとメモリ上の鍵が破棄され、それ以降のCRUDは拒否されます。

## 対応する主なコード

- `apps/api/src/services/entry-service.ts`: CRUD、入力検証、ロック判定
- `apps/api/src/services/crypto-service.ts`: AES-256-GCM暗号化・復号、保管庫鍵の保持
- `apps/api/src/db/database.ts`: SQLite接続、テーブル初期化
- `packages/shared/src/types.ts`: Summary、完全なエントリ、更新payloadの型
