# Architecture

## 目的

個人利用のローカル Web アプリとして、パスワード管理を安全かつ段階的に実装する。

## 構成

```text
Browser UI (React)
  -> Local API (Express)
  -> SQLite
  -> Crypto Service
```

## 主要コンポーネント

### Frontend

- 保管庫初期設定画面
- ロック解除画面
- エントリ一覧画面
- エントリ編集画面
- 設定画面

### API

- `POST /vault/setup`
- `POST /vault/unlock`
- `POST /vault/lock`
- `GET /entries`
- `POST /entries`
- `GET /entries/:id`
- `PUT /entries/:id`
- `DELETE /entries/:id`
- `POST /password/generate`

## データモデル

### vault_metadata

- `id`
- `password_salt`
- `kdf_params`
- `password_verifier`
- `created_at`
- `updated_at`

### password_entries

- `id`
- `service_name`
- `login_id`
- `encrypted_password`
- `encrypted_notes`
- `url`
- `tags`
- `created_at`
- `updated_at`

## セキュリティ前提

- マスターパスワードは保存しない
- 復号鍵は解除中のみメモリ保持
- パスワードとメモは項目単位で暗号化
- 5 分間の無操作でロック
- コピーした値は一定時間後にクリップボードから消す

## 今後の拡張

- Electron 化
- 暗号化されたバックアップ出力
- タグとフォルダの高度化
- 履歴管理
- 複数端末同期
