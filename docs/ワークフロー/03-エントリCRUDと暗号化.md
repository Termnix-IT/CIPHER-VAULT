# 3. エントリCRUDと暗号化

従来形式のログインを対象に、CRUDと暗号化の流れを示します。新形式は全項目を暗号化します。[種類別エントリ](../設計.md#種類別エントリ)と[v2サービス](../設計.md#通常起動とv2サービス)を参照してください。

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

    lockCheck{現在の世代の鍵が存在し<br/>無操作期限内か}
    lockCheck -- いいえ --> locked[423<br/>保管庫はロックされています]
    lockCheck -- はい --> dispatch{操作を続行}

    dispatch -->|Create| validateCreate[共通schemaで項目・型・容量を検証]
    validateCreate --> validCreate{入力が有効か}
    validCreate -- いいえ --> badRequest[400 入力不正 / 413 上限超過]
    validCreate -- はい --> capacity{新規登録件数に空きがあるか}
    capacity -- いいえ --> badRequest
    capacity -- はい --> encryptCreate[passwordとnotesを<br/>AES-256-GCMで暗号化]
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

    dispatch -->|Update| validateUpdate[共通schemaで項目・型・容量を検証]
    validateUpdate --> validUpdate{入力が有効か}
    validUpdate -- いいえ --> badRequest
    validUpdate -- はい --> existsUpdate{対象が存在するか}
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

入力契約と数値上限は[設計](../設計.md#入力の検証と上限)にまとめています。編集上限を超える既存値も閲覧でき、拒否された更新で元の値を切り詰めることはありません。

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

## セキュリティ境界

CRUDの入口と結果返却前に、解除状態・期限・世代を検査します。ロック後の要求や古い応答は拒否し、一覧には秘密値を含めません。

従来形式の暗号化範囲・IV・認証タグは上図のとおりです。実装は `entry-service.ts` と `crypto-service.ts`、保存形式と互換性は[エントリ暗号化](../設計.md#エントリ暗号化)を参照してください。
