//! Input checks, following apps/api/src/lib/input-validation.ts, vault-entry-validation.ts and the
//! entry check in crypto/v2-format.ts. The messages and statuses are the app's own, and the parity
//! test feeds the same inputs to both. A stored entry the app rejects would stop it from unlocking
//! the whole vault, so stored entries are checked as strictly as the app checks them.
//!
//! Inputs arrive as JSON, so the TypeScript checks for accessors, prototypes and lone surrogates
//! have nothing to catch here: such values cannot be expressed, and the screen refuses lone
//! surrogates before sending.

use crate::error::{Result, VaultError};
use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use serde_json::{Map, Value, json};

pub const MAX_ENTRIES: usize = 10000;
const REQUEST_BYTES: usize = 1024 * 1024;
const MASTER_PASSWORD_BYTES: usize = 1024 * 1024;
pub const BACKUP_PLAINTEXT_BYTES: usize = 11 * 1024 * 1024;
pub const BACKUP_FILE_BYTES: usize = 16 * 1024 * 1024;
const BACKUP_PASSPHRASE_BYTES: usize = 4096;
const RESTORE_REQUEST_BYTES: usize = 18 * 1024 * 1024;
const ID_BYTES: usize = 128;
const SERVICE_NAME_BYTES: usize = 1024;
const LOGIN_ID_BYTES: usize = 4096;
const PASSWORD_BYTES: usize = 64 * 1024;
const NOTES_BYTES: usize = 256 * 1024;
const URL_BYTES: usize = 8192;
const GROUP_BYTES: usize = 1024;
const TAGS: usize = 100;
const TAG_BYTES: usize = 256;
const EXTRA_SECRETS: usize = 8;
const EXTRA_LABEL_BYTES: usize = 256;
const MIN_MASTER_PASSWORD_LENGTH: usize = 12;
pub const UNGROUPED_GROUP_NAME: &str = "グループなし";
const FIXED_FINANCIAL_LABELS: [&str; 4] = ["ログインID", "ログインパスワード", "取引パスワード", "URL"];
const COMMON_FIELDS: [&str; 5] = ["serviceName", "notes", "url", "tags", "group"];
const LOGIN_FIELDS: [&str; 7] = ["serviceName", "loginId", "password", "notes", "url", "tags", "group"];
const FINANCIAL_FIELDS: [&str; 4] = ["loginId", "loginPassword", "tradingPassword", "extraSecrets"];
const INVALID_ITEM: &str = "項目の形式が正しくありません";
pub const INVALID_ENTRY: &str = "エントリの形式が正しくありません";

fn invalid<T>() -> Result<T> {
    Err(VaultError::bad_request(INVALID_ITEM))
}

/// String.prototype.trim. Rust's trim differs: it keeps U+FEFF and removes U+0085.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(|c| matches!(c, '\u{9}'..='\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'))
}

/// The length JavaScript reports, in UTF-16 code units.
pub fn js_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// parseRecord: an object whose keys are all among `fields`. `None` is a missing argument.
fn record<'a>(value: Option<&'a Value>, fields: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.and_then(Value::as_object).ok_or_else(|| VaultError::bad_request("入力はオブジェクトで指定してください"))?;
    if object.keys().all(|key| fields.contains(&key.as_str())) { Ok(object) } else { Err(VaultError::bad_request("未対応の入力項目があります")) }
}

fn text<'a>(value: Option<&'a Value>, label: &str, max_bytes: usize) -> Result<&'a str> {
    let text = value.and_then(Value::as_str).ok_or_else(|| VaultError::bad_request(format!("{label}は文字列で指定してください")))?;
    // UTF-8 is never shorter than UTF-16, so the byte count covers the app's length check too.
    if text.len() > max_bytes {
        return Err(VaultError::too_large(format!("{label}の容量が上限を超えています（{max_bytes} byteまで）")));
    }
    Ok(text)
}

/// parseClipboardText: the text the screen asks the desktop to copy.
pub fn parse_clipboard_text(value: Option<&Value>) -> Result<&str> {
    text(value, "コピーする内容", 1024 * 1024)
}

/// `input.field ?? ""`
fn optional_text<'a>(value: Option<&'a Value>, label: &str, max_bytes: usize) -> Result<&'a str> {
    match value {
        None | Some(Value::Null) => Ok(""),
        some => text(some, label, max_bytes),
    }
}

/// serde_json and JSON.stringify escape the same characters, so the sizes agree.
fn json_size(value: &Value, max_bytes: usize) -> Result<()> {
    let size = serde_json::to_string(value).map_err(|_| VaultError::bad_request(INVALID_ITEM))?.len();
    if size > max_bytes { Err(VaultError::too_large("リクエストの容量が上限を超えています")) } else { Ok(()) }
}

fn trimmed_or_null(value: &str) -> Value {
    match js_trim(value) {
        "" => Value::Null,
        trimmed => json!(trimmed),
    }
}

/// `value || null`
fn empty_to_null(value: String) -> Value {
    if value.is_empty() { Value::Null } else { json!(value) }
}

/// parseMasterPassword. An existing password is never trimmed or normalized.
pub fn parse_master_password(value: Option<&Value>, setup: bool) -> Result<String> {
    let input = record(value, &["masterPassword"])?;
    let password = text(input.get("masterPassword"), "マスターパスワード", MASTER_PASSWORD_BYTES)?;
    if setup && js_length(password) < MIN_MASTER_PASSWORD_LENGTH {
        return Err(VaultError::bad_request("マスターパスワードは12文字以上で入力してください"));
    }
    json_size(&json!({ "masterPassword": password }), REQUEST_BYTES)?;
    Ok(password.to_string())
}

/// parseBackupPayload: the passphrase, and for a restore the file content as the screen read it.
pub fn parse_backup_payload(value: Option<&Value>, restore: bool) -> Result<(String, Option<String>)> {
    let input = record(value, if restore { &["passphrase", "content"] } else { &["passphrase"] })?;
    if !input.get("passphrase").and_then(Value::as_str).is_some_and(|text| (12..=1024).contains(&js_length(text))) {
        return Err(VaultError::bad_request("バックアップ用パスフレーズは12〜1024文字で入力してください"));
    }
    let passphrase = text(input.get("passphrase"), "バックアップ用パスフレーズ", BACKUP_PASSPHRASE_BYTES)?.to_string();
    if !restore {
        return Ok((passphrase, None));
    }
    let content = text(input.get("content"), "バックアップファイル", BACKUP_FILE_BYTES)?;
    json_size(&json!({ "passphrase": passphrase, "content": content }), RESTORE_REQUEST_BYTES)?;
    Ok((passphrase, Some(content.to_string())))
}

pub fn parse_reset_payload(value: Option<&Value>) -> Result<()> {
    let input = record(value, &["confirmation"])?;
    if input.get("confirmation").and_then(Value::as_str) == Some("RESET_ALL_DATA") { Ok(()) } else { Err(VaultError::bad_request("保管庫のリセット確認が必要です")) }
}

/// parseEntryPayload in write mode, then the normalization the services apply before saving:
/// the names and URL are trimmed, an empty group becomes null and the password is kept exactly.
pub fn parse_login(value: Option<&Value>) -> Result<Value> {
    let input = record(value, &LOGIN_FIELDS)?;
    let service_name = text(input.get("serviceName"), "サービス名", SERVICE_NAME_BYTES)?;
    let login_id = text(input.get("loginId"), "ログインID", LOGIN_ID_BYTES)?;
    let password = text(input.get("password"), "パスワード", PASSWORD_BYTES)?;
    if js_trim(service_name).is_empty() {
        return Err(VaultError::bad_request("サービス名は必須です"));
    }
    if js_trim(login_id).is_empty() {
        return Err(VaultError::bad_request("ログインIDは必須です"));
    }
    if password.is_empty() {
        return Err(VaultError::bad_request("パスワードは必須です"));
    }
    let notes = optional_text(input.get("notes"), "メモ", NOTES_BYTES)?;
    let url = optional_text(input.get("url"), "URL", URL_BYTES)?;
    let group = optional_text(input.get("group"), "グループ", GROUP_BYTES)?;
    let raw_tags = match input.get("tags") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) => items.as_slice(),
        Some(_) => return Err(VaultError::bad_request("タグは文字列の配列で指定してください")),
    };
    if raw_tags.len() > TAGS {
        return Err(VaultError::too_large("タグは100件まで指定できます"));
    }
    let tags = raw_tags.iter().map(|tag| text(Some(tag), "タグ", TAG_BYTES)).collect::<Result<Vec<_>>>()?;
    json_size(&json!({ "serviceName": service_name, "loginId": login_id, "password": password, "notes": notes, "url": url, "group": group, "tags": tags }), REQUEST_BYTES)?;
    Ok(json!({ "serviceName": js_trim(service_name), "loginId": js_trim(login_id), "password": password, "notes": notes,
        "url": js_trim(url), "tags": tags, "group": trimmed_or_null(group) }))
}

fn date(value: Option<&Value>, month_only: bool) -> Result<String> {
    let text = match value {
        None => return Ok(String::new()),
        Some(Value::String(text)) => text.as_str(),
        Some(_) => return invalid(),
    };
    if text.is_empty() {
        return Ok(String::new());
    }
    let shape = if month_only { "dddd-dd" } else { "dddd-dd-dd" };
    let matches_shape = text.len() == shape.len() && text.bytes().zip(shape.bytes()).all(|(byte, kind)| if kind == b'd' { byte.is_ascii_digit() } else { byte == kind });
    if !matches_shape {
        return invalid();
    }
    let number = |range: std::ops::Range<usize>| text[range].parse::<u32>().unwrap_or(0);
    let day = if month_only { 1 } else { number(8..10) };
    if NaiveDate::from_ymd_opt(number(0..4) as i32, number(5..7), day).is_none() {
        return invalid();
    }
    Ok(text.to_string())
}

struct Common<'a> {
    service_name: &'a str,
    notes: &'a str,
    url: &'a str,
    group: &'a str,
    tags: Vec<&'a str>,
}

impl Common<'_> {
    /// The fields the service stores for every additional kind.
    fn normalized(&self) -> Map<String, Value> {
        let Value::Object(fields) = json!({ "serviceName": js_trim(self.service_name), "notes": self.notes, "url": js_trim(self.url), "tags": self.tags, "group": trimmed_or_null(self.group) }) else {
            unreachable!("json! with braces builds an object")
        };
        fields
    }
}

/// Stored entries come from the app itself or a backup, so the per-field write limits do not apply.
fn common(input: &Map<String, Value>, stored: bool) -> Result<Common<'_>> {
    let limit = |bytes: usize| if stored { BACKUP_PLAINTEXT_BYTES } else { bytes };
    let service_name = text(input.get("serviceName"), "名前", limit(SERVICE_NAME_BYTES))?;
    if js_trim(service_name).is_empty() {
        return invalid();
    }
    let notes = optional_text(input.get("notes"), "メモ", limit(NOTES_BYTES))?;
    let url = optional_text(input.get("url"), "URL", limit(URL_BYTES))?;
    let group = optional_text(input.get("group"), "グループ", limit(GROUP_BYTES))?;
    let raw_tags = match input.get("tags") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) if items.len() <= TAGS => items.as_slice(),
        Some(_) => return invalid(),
    };
    let tags = raw_tags.iter().map(|tag| text(Some(tag), "タグ", limit(TAG_BYTES))).collect::<Result<Vec<_>>>()?;
    Ok(Common { service_name, notes, url, group, tags })
}

fn extra_secrets(input: Option<&Value>) -> Result<Value> {
    let raw = match input {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) if items.len() <= EXTRA_SECRETS => items.as_slice(),
        Some(_) => return invalid(),
    };
    let mut labels: Vec<&str> = FIXED_FINANCIAL_LABELS.to_vec();
    let mut result = Vec::with_capacity(raw.len());
    for item in raw {
        let item = record(Some(item), &["label", "value"])?;
        let label = js_trim(text(item.get("label"), "追加の秘密の名前", EXTRA_LABEL_BYTES)?);
        let value = text(item.get("value"), "追加の秘密", PASSWORD_BYTES)?;
        if label.is_empty() || value.is_empty() {
            return invalid();
        }
        if labels.contains(&label) {
            return Err(VaultError::bad_request(format!("「{label}」は名前に使えないか、すでに使われています")));
        }
        labels.push(label);
        result.push(json!({ "label": label, "value": value }));
    }
    Ok(Value::Array(result))
}

fn detail_field(kind: &str) -> &'static str {
    match kind {
        "apiKey" => "apiKey",
        "financial" => "financial",
        _ => "card",
    }
}

fn fields_with(extra: &[&'static str]) -> Vec<&'static str> {
    COMMON_FIELDS.into_iter().chain(extra.iter().copied()).collect()
}

/// parseVaultEntryPayload, returning what the v2 service stores. A login has no `type`.
pub fn parse_vault_entry(value: Option<&Value>) -> Result<Value> {
    parse_vault_entry_as(value, false)
}

fn parse_vault_entry_as(input: Option<&Value>, stored: bool) -> Result<Value> {
    let value = record(input, &fields_with(&["loginId", "password", "type", "apiKey", "card", "financial"]))?;
    let Some(kind) = value.get("type") else {
        return parse_login(input);
    };
    let kind = match kind.as_str() {
        Some("login") => {
            let mut login = record(input, &fields_with(&["loginId", "password", "type"]))?.clone();
            login.remove("type");
            return parse_login(Some(&Value::Object(login)));
        }
        Some(kind @ ("apiKey" | "creditCard" | "financial")) => kind,
        _ => return invalid(),
    };
    let detail_name = detail_field(kind);
    let parsed = record(input, &fields_with(&["type", detail_name]))?;
    let metadata = common(parsed, stored)?;
    let detail = parsed.get(detail_name);
    let (raw, normalized) = match kind {
        "financial" => {
            let financial = record(detail, &FINANCIAL_FIELDS)?;
            let login_id = text(financial.get("loginId"), "ログインID", LOGIN_ID_BYTES)?;
            let login_password = text(financial.get("loginPassword"), "ログインパスワード", PASSWORD_BYTES)?;
            if js_trim(login_id).is_empty() || login_password.is_empty() {
                return invalid(); // The exact credentials are kept, never trimmed.
            }
            let trading_password = optional_text(financial.get("tradingPassword"), "取引パスワード", PASSWORD_BYTES)?;
            let extras = extra_secrets(financial.get("extraSecrets"))?;
            let normalized = json!({ "loginId": js_trim(login_id), "loginPassword": login_password, "tradingPassword": trading_password, "extraSecrets": extras });
            (json!({ "loginId": login_id, "loginPassword": login_password, "tradingPassword": trading_password, "extraSecrets": extras }), normalized)
        }
        "apiKey" => {
            let api_key = record(detail, &["key", "keyId", "expiresOn"])?;
            let key = text(api_key.get("key"), "キー／トークン", PASSWORD_BYTES)?;
            if key.is_empty() {
                return invalid();
            }
            let key_id = optional_text(api_key.get("keyId"), "キーID", LOGIN_ID_BYTES)?;
            let expires_on = date(api_key.get("expiresOn"), false)?;
            (json!({ "key": key, "keyId": key_id, "expiresOn": expires_on }), json!({ "key": key, "keyId": key_id, "expiresOn": empty_to_null(expires_on) }))
        }
        _ => {
            let card = record(detail, &["number", "cardholder", "expiryMonth", "securityCode"])?;
            let number: String = text(card.get("number"), "カード番号", 64)?.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
            if !(12..=19).contains(&number.len()) || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                return invalid();
            }
            let security_code = optional_text(card.get("securityCode"), "セキュリティコード", 4)?;
            let code_is_valid = (3..=4).contains(&security_code.len()) && security_code.bytes().all(|byte| byte.is_ascii_digit());
            if !security_code.is_empty() && !code_is_valid {
                return invalid();
            }
            let cardholder = optional_text(card.get("cardholder"), "名義", 1024)?;
            let expiry_month = date(card.get("expiryMonth"), true)?;
            (json!({ "number": number, "cardholder": cardholder, "expiryMonth": expiry_month, "securityCode": security_code }),
             json!({ "number": number, "cardholder": cardholder, "expiryMonth": empty_to_null(expiry_month), "securityCode": security_code }))
        }
    };
    let size = json!({ "serviceName": metadata.service_name, "notes": metadata.notes, "url": metadata.url, "group": metadata.group, "tags": metadata.tags, "type": kind, detail_name: raw });
    json_size(&size, if stored { BACKUP_PLAINTEXT_BYTES } else { REQUEST_BYTES })?;
    let mut fields = metadata.normalized();
    fields.insert("type".into(), json!(kind));
    fields.insert(detail_name.into(), normalized);
    Ok(Value::Object(fields))
}

/// An existing legacy vault stores logins only.
pub fn require_legacy_item(input: Option<&Value>) -> Result<()> {
    match input.and_then(Value::as_object).and_then(|object| object.get("type")) {
        None => Ok(()),
        Some(Value::String(kind)) if kind == "login" => Ok(()),
        Some(_) => Err(VaultError::conflict("APIキー・カード・銀行/証券の保存には新しい形式への移行が必要です。保管庫の管理から移行してください")),
    }
}

pub fn parse_entry_id(value: Option<&Value>) -> Result<String> {
    let id = text(value, "エントリID", ID_BYTES)?;
    if id.is_empty() || id.contains('\0') {
        return Err(VaultError::bad_request("エントリIDの形式が正しくありません"));
    }
    Ok(id.to_string())
}

/// parseEntriesGroupPayload. Repeated ids count once, in the order first given.
pub fn parse_group_payload(value: Option<&Value>) -> Result<(Vec<String>, Option<String>)> {
    let input = record(value, &["ids", "group"])?;
    let raw_ids = input.get("ids").and_then(Value::as_array).ok_or_else(|| VaultError::bad_request("対象の項目は配列で指定してください"))?;
    if raw_ids.is_empty() {
        return Err(VaultError::bad_request("対象の項目を1件以上選んでください"));
    }
    if raw_ids.len() > MAX_ENTRIES {
        return Err(VaultError::too_large("対象の項目は10000件まで指定できます"));
    }
    let mut ids: Vec<String> = Vec::with_capacity(raw_ids.len());
    let mut seen = std::collections::HashSet::new();
    for raw in raw_ids {
        let id = parse_entry_id(Some(raw))?;
        if seen.insert(id.clone()) {
            ids.push(id);
        }
    }
    if input.get("group") == Some(&Value::Null) {
        return Ok((ids, None));
    }
    let group = js_trim(text(input.get("group"), "グループ", GROUP_BYTES)?);
    if group.is_empty() {
        return Err(VaultError::bad_request("グループ名を入力してください"));
    }
    if group == UNGROUPED_GROUP_NAME {
        return Err(VaultError::bad_request(format!("「{UNGROUPED_GROUP_NAME}」はグループ名に使えません")));
    }
    Ok((ids, Some(group.to_string())))
}

/// `new Date().toISOString()`
pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// A date in the one form `toISOString` writes, which also makes the text sort by time.
fn canonical_date(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    let parsed = DateTime::parse_from_rfc3339(text).ok()?;
    (parsed.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Millis, true) == text).then_some(text)
}

pub(crate) fn is_entry_uuid(id: &str) -> bool {
    id.len() == 36 && id.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

/// validateEntryPlaintext: every entry is checked when it is read, and before it is sealed.
pub fn validate_stored_entry(entry: &Value, expected_id: &str) -> Result<()> {
    // The list icon (format 4) is checked on its own, and the rest of the entry as before.
    let without_icon;
    let entry = match entry.get("icon") {
        Some(icon) => {
            crate::icons::parse_icon(icon).map_err(|_| VaultError::bad_request(INVALID_ENTRY))?;
            let mut copy = entry.clone();
            copy.as_object_mut().map(|object| object.remove("icon"));
            without_icon = copy;
            &without_icon
        }
        None => entry,
    };
    let checked = match entry["type"].as_str() {
        Some("apiKey" | "creditCard" | "financial") => validate_additional(entry, expected_id),
        _ => validate_login(entry, expected_id),
    };
    checked.ok_or_else(|| VaultError::bad_request(INVALID_ENTRY))
}

fn validate_login(entry: &Value, expected_id: &str) -> Option<()> {
    const FIELDS: [&str; 11] = ["id", "serviceName", "loginId", "password", "notes", "url", "tags", "group", "createdAt", "updatedAt", "passwordChangedAt"];
    let object = entry.as_object()?;
    if object.len() != FIELDS.len() || !FIELDS.iter().all(|field| object.contains_key(*field)) || object["id"] != expected_id {
        return None;
    }
    let texts: Vec<&str> = ["serviceName", "loginId", "password", "notes", "url"].iter().map(|field| object[*field].as_str()).collect::<Option<_>>()?;
    if js_trim(texts[0]).is_empty() || js_trim(texts[1]).is_empty() || texts[2].is_empty() {
        return None;
    }
    if !(object["group"].is_null() || object["group"].is_string()) || !object["tags"].as_array()?.iter().all(Value::is_string) {
        return None;
    }
    let created = canonical_date(object.get("createdAt"))?;
    let updated = canonical_date(object.get("updatedAt"))?;
    let changed = &object["passwordChangedAt"];
    let changed_is_valid = changed.is_null() || canonical_date(Some(changed)).is_some_and(|changed| created <= changed && changed <= updated);
    (created <= updated && changed_is_valid).then_some(())
}

/// validateAdditionalEntry: the stored record must also pass the write checks, with the larger
/// limits a backup allows.
fn validate_additional(entry: &Value, expected_id: &str) -> Option<()> {
    let kind = entry["type"].as_str()?;
    let detail_name = detail_field(kind);
    let allowed: Vec<&str> = COMMON_FIELDS.into_iter().chain(["id", "type", "createdAt", "updatedAt", detail_name]).collect();
    let object = record(Some(entry), &allowed).ok()?;
    let id = object.get("id")?.as_str()?;
    if !is_entry_uuid(id) || id != expected_id {
        return None;
    }
    if !["serviceName", "notes", "url"].iter().all(|field| object.get(*field).is_some_and(Value::is_string)) {
        return None;
    }
    let group = object.get("group")?;
    if !(group.is_null() || group.is_string()) || !object.get("tags")?.is_array() {
        return None;
    }
    let created = canonical_date(object.get("createdAt"))?;
    let updated = canonical_date(object.get("updatedAt"))?;
    if created > updated {
        return None;
    }
    let mut payload = object.clone();
    for field in ["id", "createdAt", "updatedAt"] {
        payload.remove(field);
    }
    payload.insert("group".into(), if group.is_null() { json!("") } else { group.clone() });
    if kind == "financial" {
        let financial = record(object.get("financial"), &FINANCIAL_FIELDS).ok()?;
        if !["loginId", "loginPassword", "tradingPassword"].iter().all(|field| financial.get(*field).is_some_and(Value::is_string)) || !financial.get("extraSecrets")?.is_array() {
            return None;
        }
    } else {
        let (fields, date_field, texts): (&[&str], &str, &[&str]) = if kind == "apiKey" {
            (&["key", "keyId", "expiresOn"], "expiresOn", &["key", "keyId"])
        } else {
            (&["number", "cardholder", "expiryMonth", "securityCode"], "expiryMonth", &["number", "cardholder", "securityCode"])
        };
        let mut detail = record(object.get(detail_name), fields).ok()?.clone();
        match detail.get(date_field) {
            Some(Value::Null) => {
                detail.insert(date_field.into(), json!(""));
            }
            Some(Value::String(date)) if !date.is_empty() => {}
            _ => return None,
        }
        if !texts.iter().all(|field| detail.get(*field).is_some_and(Value::is_string)) {
            return None;
        }
        if kind == "creditCard" && detail["number"].as_str()?.contains([' ', '-']) {
            return None;
        }
        payload.insert(detail_name.into(), Value::Object(detail));
    }
    parse_vault_entry_as(Some(&Value::Object(payload)), true).ok().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Value {
        json!({ "serviceName": " 合成 ", "loginId": " id ", "password": " keep " })
    }

    fn error(result: Result<Value>) -> (u16, String) {
        let error = result.unwrap_err();
        (error.status, error.message)
    }

    #[test]
    fn trimming_matches_javascript_rather_than_rust() {
        assert_eq!(js_trim("\u{feff}\u{a0} x \u{3000}\n"), "x");
        assert_eq!(js_trim("\u{85}x\u{85}"), "\u{85}x\u{85}");
        assert_eq!(js_trim("\u{200b}x"), "\u{200b}x");
        assert_ne!("\u{feff}x".trim(), js_trim("\u{feff}x"), "the difference this function exists for");
    }

    #[test]
    fn a_login_is_normalized_but_its_password_is_kept_exactly() {
        let parsed = parse_vault_entry(Some(&login())).unwrap();
        assert_eq!(parsed, json!({ "serviceName": "合成", "loginId": "id", "password": " keep ", "notes": "", "url": "", "tags": [], "group": null }));
        let mut typed = login();
        typed["type"] = json!("login");
        assert_eq!(parse_vault_entry(Some(&typed)).unwrap(), parsed);
        assert_eq!(error(parse_login(Some(&typed))), (400, "未対応の入力項目があります".into()), "a legacy vault takes no type");
    }

    #[test]
    fn limits_count_utf8_bytes_and_report_the_app_statuses() {
        let mut input = login();
        input["password"] = json!("あ".repeat(PASSWORD_BYTES / 3 + 1));
        assert_eq!(error(parse_login(Some(&input))), (413, format!("パスワードの容量が上限を超えています（{PASSWORD_BYTES} byteまで）")));
        let mut input = login();
        input["tags"] = json!(vec!["t"; TAGS + 1]);
        assert_eq!(error(parse_login(Some(&input))), (413, "タグは100件まで指定できます".into()));
        input["tags"] = json!("t");
        assert_eq!(error(parse_login(Some(&input))), (400, "タグは文字列の配列で指定してください".into()));
        assert_eq!(error(parse_login(Some(&json!([])))), (400, "入力はオブジェクトで指定してください".into()));
        assert_eq!(error(parse_login(None)), (400, "入力はオブジェクトで指定してください".into()));
        let mut input = login();
        input["serviceName"] = json!(" \u{3000}");
        assert_eq!(error(parse_login(Some(&input))), (400, "サービス名は必須です".into()));
    }

    #[test]
    fn master_passwords_count_javascript_characters_and_are_never_trimmed() {
        let twelve_astral = "🔐".repeat(6);
        assert_eq!(js_length(&twelve_astral), 12);
        assert_eq!(parse_master_password(Some(&json!({ "masterPassword": twelve_astral })), true).unwrap(), twelve_astral);
        let short = parse_master_password(Some(&json!({ "masterPassword": "あ".repeat(11) })), true).unwrap_err();
        assert_eq!(short, VaultError::bad_request("マスターパスワードは12文字以上で入力してください"));
        assert_eq!(parse_master_password(Some(&json!({ "masterPassword": " x " })), false).unwrap(), " x ");
        assert_eq!(parse_master_password(Some(&json!({ "masterPassword": "x", "extra": 1 })), false).unwrap_err().message, "未対応の入力項目があります");
        let huge = "a".repeat(MASTER_PASSWORD_BYTES);
        assert_eq!(parse_master_password(Some(&json!({ "masterPassword": huge })), false).unwrap_err(), VaultError::too_large("リクエストの容量が上限を超えています"));
    }

    #[test]
    fn dates_must_exist_and_keep_their_exact_shape() {
        for (value, month_only, valid) in [("2028-02-29", false, true), ("2029-02-29", false, false), ("2029-2-1", false, false), ("2029-02-28\n", false, false),
            ("２０２９-02-28", false, false), ("2029-12", true, true), ("2029-13", true, false), ("2029-00", true, false), ("", false, true)] {
            assert_eq!(date(Some(&json!(value)), month_only).is_ok(), valid, "{value:?}");
        }
        assert!(date(Some(&Value::Null), false).is_err());
        assert_eq!(date(None, false).unwrap(), "");
    }

    fn stored(kind: &str) -> Value {
        let id = "11111111-1111-4111-8111-111111111111";
        let detail = match kind {
            "apiKey" => json!({ "type": "apiKey", "apiKey": { "key": "k", "keyId": "", "expiresOn": null } }),
            "creditCard" => json!({ "type": "creditCard", "card": { "number": "4111111111111111", "cardholder": "", "expiryMonth": "2030-01", "securityCode": "" } }),
            "financial" => json!({ "type": "financial", "financial": { "loginId": "i", "loginPassword": "p", "tradingPassword": "", "extraSecrets": [] } }),
            _ => json!({ "loginId": "i", "password": "p", "passwordChangedAt": null }),
        };
        let mut entry = json!({ "id": id, "serviceName": "s", "notes": "", "url": "", "tags": [], "group": null,
            "createdAt": "2029-01-01T00:00:00.000Z", "updatedAt": "2029-01-02T00:00:00.000Z" });
        entry.as_object_mut().unwrap().extend(detail.as_object().unwrap().clone());
        entry
    }

    #[test]
    fn stored_entries_that_the_app_would_reject_are_caught() {
        let id = "11111111-1111-4111-8111-111111111111";
        for kind in ["login", "apiKey", "creditCard", "financial"] {
            let entry = stored(kind);
            assert_eq!(validate_stored_entry(&entry, id), Ok(()), "{kind}");
            assert!(validate_stored_entry(&entry, "22222222-2222-4222-8222-222222222222").is_err(), "{kind}: another id");
            let change = |field: &str, value: Value| {
                let mut changed = entry.clone();
                changed[field] = value;
                validate_stored_entry(&changed, id).is_err()
            };
            assert!(change("createdAt", json!("2030-01-01T00:00:00.000Z")), "{kind}: created after updated");
            assert!(change("updatedAt", json!("2029-01-02T00:00:00Z")), "{kind}: not the canonical form");
            assert!(change("serviceName", json!(" ")), "{kind}: an empty name");
            assert!(change("unexpected", json!(1)), "{kind}: an unknown field");
            assert!(change("group", json!(1)), "{kind}: a group that is not text");
        }
        let mut card = stored("creditCard");
        card["card"]["number"] = json!("4111 1111 1111 1111");
        assert!(validate_stored_entry(&card, id).is_err(), "a stored card number has no separators");
        let mut key = stored("apiKey");
        key["apiKey"]["expiresOn"] = json!("");
        assert!(validate_stored_entry(&key, id).is_err(), "an unknown expiry is stored as null");
        let mut login = stored("login");
        login["passwordChangedAt"] = json!("2031-01-01T00:00:00.000Z");
        assert!(validate_stored_entry(&login, id).is_err(), "changed after updated");
        login["passwordChangedAt"] = json!("2029-01-01T12:00:00.000Z");
        assert!(validate_stored_entry(&login, "a login id may be any text").is_err());
        login["id"] = json!("a login id may be any text");
        assert_eq!(validate_stored_entry(&login, "a login id may be any text"), Ok(()));
        let mut typed_login = stored("login");
        typed_login["type"] = json!("login");
        assert!(validate_stored_entry(&typed_login, id).is_err(), "a stored login has no type");
    }

    #[test]
    fn group_payloads_follow_the_app_rules() {
        let (ids, group) = parse_group_payload(Some(&json!({ "ids": ["a", "b", "a"], "group": " g " }))).unwrap();
        assert_eq!((ids, group), (vec!["a".to_string(), "b".to_string()], Some("g".to_string())));
        assert_eq!(parse_group_payload(Some(&json!({ "ids": ["a"], "group": null }))).unwrap().1, None);
        assert_eq!(parse_group_payload(Some(&json!({ "ids": [], "group": "g" }))).unwrap_err().message, "対象の項目を1件以上選んでください");
        assert_eq!(parse_group_payload(Some(&json!({ "ids": ["a"], "group": UNGROUPED_GROUP_NAME }))).unwrap_err().message, "「グループなし」はグループ名に使えません");
        assert_eq!(parse_group_payload(Some(&json!({ "ids": [""], "group": "g" }))).unwrap_err().message, "エントリIDの形式が正しくありません");
    }
}
