# 3. エントリCRUDと暗号化

エントリのCRUDと暗号化の流れです。entryは種類によらず全体を1つの暗号envelopeにします。詳しくは[種類別エントリ](../設計.md#種類別エントリ)と[v2サービス](../設計.md#通常起動とv2サービス)を参照してください。

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
    capacity -- はい --> reserveCreate[(nonceを予約しcommit)]
    reserveCreate --> encryptCreate[entry全体を<br/>AES-256-GCMで暗号化]
    encryptCreate --> insert[(revision 1で保存)]
    insert --> createdResponse[作成したエントリを返す]

    dispatch -->|Read list| selectList[(全entryを読む)]
    selectList --> decryptList[各entryを認証・復号]
    decryptList --> summaries[秘密情報を除いたSummaryへ変換<br/>アイコンを含む]
    summaries --> listResponse[一覧を返す]

    dispatch -->|Read detail| selectDetail[(IDで1件を読む)]
    selectDetail --> foundDetail{存在するか}
    foundDetail -- いいえ --> notFound[404 エントリなし]
    foundDetail -- はい --> decryptDetail[ID・revisionを照合して<br/>認証・復号]
    decryptDetail --> detailResponse[完全なエントリを返す]

    dispatch -->|Update| validateUpdate[共通schemaで項目・型・容量を検証]
    validateUpdate --> validUpdate{入力が有効か}
    validUpdate -- いいえ --> badRequest
    validUpdate -- はい --> existsUpdate{対象が存在するか}
    existsUpdate -- いいえ --> notFound
    existsUpdate -- はい --> merge[作成日・変更日・アイコンを引き継ぐ]
    merge --> reserveUpdate[(nonceを予約しcommit)]
    reserveUpdate --> encryptUpdate[entry全体を再暗号化]
    encryptUpdate --> updateRow[(revision+1で保存)]
    updateRow --> updatedResponse[更新済みエントリを返す]

    dispatch -->|Delete| existsDelete{対象が存在するか}
    existsDelete -- いいえ --> notFound
    existsDelete -- はい --> deleteRow[(暗号文を除き<br/>IDとrevisionをtombstoneで残す)]
    deleteRow --> deleteResponse[success: trueを返す]
```

入力契約と数値上限は[設計](../設計.md#入力の検証と上限)にまとめています。編集上限を超える既存値も閲覧でき、拒否された更新で元の値を切り詰めることはありません。

## 保存データの暗号化範囲

```mermaid
flowchart LR
    master[マスターパスワード] -->|scrypt + Salt| slotKey[slotの鍵]
    slotKey --> slot[(password slot)]
    root[32 byte root鍵] --> slot
    root --> memory[(解錠中のプロセスメモリ)]
    memory -->|HKDF| entryKey[entry用の鍵]

    entry[entry全体のJSON<br/>サービス名・ログインID・password・メモ・URL<br/>タグ・グループ・日時・アイコン] --> encrypt[AES-256-GCM<br/>AADにvaultId・keyId・entryId・revision]
    entryKey --> encrypt
    encrypt --> envelope[(vault_entriesのenvelope)]

    ids[entryId / revision / 件数] --> plain[(平文)]
```

## セキュリティ境界

CRUDの入口と結果返却前に、解除状態・期限・世代を検査します。ロック後の要求や古い応答は拒否し、一覧には秘密値を含めません。

実装は `crates/vault-core` の `v2.rs` と `crypto.rs`、暗号形式は[v2の暗号形式](../設計.md#v2の暗号形式)、保存形式と版は[v2保存層](../設計.md#v2保存層)を参照してください。
