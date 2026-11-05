//! Input checks for writes, following apps/api/src/lib/input-validation.ts and
//! vault-entry-validation.ts. verify-write.mjs feeds the same inputs to both and compares them,
//! because a stored entry the app rejects would stop it from unlocking the whole vault.

use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

pub const MAX_ENTRIES: usize = 10000;
const REQUEST_BYTES: usize = 1024 * 1024;
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
const UNGROUPED_GROUP_NAME: &str = "グループなし";
const FIXED_FINANCIAL_LABELS: [&str; 4] = ["ログインID", "ログインパスワード", "取引パスワード", "URL"];
const COMMON_FIELDS: [&str; 5] = ["serviceName", "notes", "url", "tags", "group"];
const INVALID_ITEM: &str = "項目の形式が正しくありません";
const INVALID_ENTRY: &str = "エントリの形式が正しくありません";

type Result<T> = std::result::Result<T, String>;

fn invalid<T>() -> Result<T> {
    Err(INVALID_ITEM.into())
}

/// String.prototype.trim. Rust's trim differs: it keeps U+FEFF and removes U+0085.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(|c| matches!(c, '\u{9}'..='\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'))
}

fn record<'a>(value: Option<&'a Value>, fields: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.and_then(Value::as_object).ok_or("入力はオブジェクトで指定してください")?;
    if object.keys().all(|key| fields.contains(&key.as_str())) { Ok(object) } else { Err("未対応の入力項目があります".into()) }
}

fn text<'a>(value: Option<&'a Value>, label: &str, max_bytes: usize) -> Result<&'a str> {
    let text = value.and_then(Value::as_str).ok_or_else(|| format!("{label}は文字列で指定してください"))?;
    if text.len() > max_bytes {
        return Err(format!("{label}の容量が上限を超えています（{max_bytes} byteまで）"));
    }
    Ok(text)
}

/// `input.field ?? ""`
fn optional_text<'a>(value: Option<&'a Value>, label: &str, max_bytes: usize) -> Result<&'a str> {
    match value {
        None | Some(Value::Null) => Ok(""),
        some => text(some, label, max_bytes),
    }
}

fn json_size(value: &Value) -> Result<()> {
    let size = serde_json::to_string(value).map_err(|_| INVALID_ITEM)?.len();
    if size > REQUEST_BYTES { Err("リクエストの容量が上限を超えています".into()) } else { Ok(()) }
}

fn trimmed_or_null(value: &str) -> Value {
    match js_trim(value) {
        "" => Value::Null,
        trimmed => json!(trimmed),
    }
}

/// Null when the value is empty, matching `value || null`.
fn empty_to_null(value: String) -> Value {
    if value.is_empty() { Value::Null } else { json!(value) }
}

/// Mirrors parseEntryPayload, then the normalization the services apply before saving.
pub fn parse_login(input: &Value) -> Result<Value> {
    let input = record(Some(input), &["serviceName", "loginId", "password", "notes", "url", "tags", "group"])?;
    let service_name = text(input.get("serviceName"), "サービス名", SERVICE_NAME_BYTES)?;
    let login_id = text(input.get("loginId"), "ログインID", LOGIN_ID_BYTES)?;
    let password = text(input.get("password"), "パスワード", PASSWORD_BYTES)?;
    if js_trim(service_name).is_empty() {
        return Err("サービス名は必須です".into());
    }
    if js_trim(login_id).is_empty() {
        return Err("ログインIDは必須です".into());
    }
    if password.is_empty() {
        return Err("パスワードは必須です".into());
    }
    let notes = optional_text(input.get("notes"), "メモ", NOTES_BYTES)?;
    let url = optional_text(input.get("url"), "URL", URL_BYTES)?;
    let group = optional_text(input.get("group"), "グループ", GROUP_BYTES)?;
    let raw_tags = match input.get("tags") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) => items.as_slice(),
        Some(_) => return Err("タグは文字列の配列で指定してください".into()),
    };
    if raw_tags.len() > TAGS {
        return Err("タグは100件まで指定できます".into());
    }
    let tags = raw_tags.iter().map(|tag| text(Some(tag), "タグ", TAG_BYTES)).collect::<Result<Vec<_>>>()?;
    json_size(&json!({ "serviceName": service_name, "loginId": login_id, "password": password, "notes": notes, "url": url, "group": group, "tags": tags }))?;
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

fn common(input: &Map<String, Value>) -> Result<Common<'_>> {
    let service_name = text(input.get("serviceName"), "名前", SERVICE_NAME_BYTES)?;
    if js_trim(service_name).is_empty() {
        return invalid();
    }
    let notes = optional_text(input.get("notes"), "メモ", NOTES_BYTES)?;
    let url = optional_text(input.get("url"), "URL", URL_BYTES)?;
    let group = optional_text(input.get("group"), "グループ", GROUP_BYTES)?;
    let raw_tags = match input.get("tags") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) if items.len() <= TAGS => items.as_slice(),
        Some(_) => return invalid(),
    };
    let tags = raw_tags.iter().map(|tag| text(Some(tag), "タグ", TAG_BYTES)).collect::<Result<Vec<_>>>()?;
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
            return Err(format!("「{label}」は名前に使えないか、すでに使われています"));
        }
        labels.push(label);
        result.push(json!({ "label": label, "value": value }));
    }
    Ok(Value::Array(result))
}

fn with_common(common: &Common<'_>, kind: &str, detail_name: &str, detail: Value) -> Value {
    let mut fields = common.normalized();
    fields.insert("type".into(), json!(kind));
    fields.insert(detail_name.into(), detail);
    Value::Object(fields)
}

fn raw_size(common: &Common<'_>, kind: &str, detail_name: &str, detail: &Value) -> Result<()> {
    json_size(&json!({ "serviceName": common.service_name, "notes": common.notes, "url": common.url, "group": common.group, "tags": common.tags, "type": kind, detail_name: detail }))
}

/// Mirrors parseVaultEntryPayload, returning what the v2 service stores. A login has no `type`.
pub fn parse_vault_entry(input: &Value) -> Result<Value> {
    let fields: Vec<&str> = COMMON_FIELDS.into_iter().chain(["loginId", "password", "type", "apiKey", "card", "financial"]).collect();
    let value = record(Some(input), &fields)?;
    let Some(kind) = value.get("type") else {
        return parse_login(input);
    };
    let detail_name = match kind.as_str() {
        Some("login") => {
            let fields: Vec<&str> = COMMON_FIELDS.into_iter().chain(["loginId", "password", "type"]).collect();
            let mut login = record(Some(input), &fields)?.clone();
            login.remove("type");
            return parse_login(&Value::Object(login));
        }
        Some("apiKey") => "apiKey",
        Some("creditCard") => "card",
        Some("financial") => "financial",
        _ => return invalid(),
    };
    let kind = kind.as_str().unwrap_or_default();
    let fields: Vec<&str> = COMMON_FIELDS.into_iter().chain(["type", detail_name]).collect();
    let parsed = record(Some(input), &fields)?;
    let metadata = common(parsed)?;
    let detail = parsed.get(detail_name);
    let (raw, stored) = match kind {
        "financial" => {
            let financial = record(detail, &["loginId", "loginPassword", "tradingPassword", "extraSecrets"])?;
            let login_id = text(financial.get("loginId"), "ログインID", LOGIN_ID_BYTES)?;
            let login_password = text(financial.get("loginPassword"), "ログインパスワード", PASSWORD_BYTES)?;
            if js_trim(login_id).is_empty() || login_password.is_empty() {
                return invalid(); // The exact credentials are kept, never trimmed.
            }
            let trading_password = optional_text(financial.get("tradingPassword"), "取引パスワード", PASSWORD_BYTES)?;
            let extras = extra_secrets(financial.get("extraSecrets"))?;
            let stored = json!({ "loginId": js_trim(login_id), "loginPassword": login_password, "tradingPassword": trading_password, "extraSecrets": extras });
            (json!({ "loginId": login_id, "loginPassword": login_password, "tradingPassword": trading_password, "extraSecrets": extras }), stored)
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
            if !security_code.is_empty() && !((3..=4).contains(&security_code.len()) && security_code.bytes().all(|byte| byte.is_ascii_digit())) {
                return invalid();
            }
            let cardholder = optional_text(card.get("cardholder"), "名義", 1024)?;
            let expiry_month = date(card.get("expiryMonth"), true)?;
            (json!({ "number": number, "cardholder": cardholder, "expiryMonth": expiry_month, "securityCode": security_code }),
             json!({ "number": number, "cardholder": cardholder, "expiryMonth": empty_to_null(expiry_month), "securityCode": security_code }))
        }
    };
    raw_size(&metadata, kind, detail_name, &raw)?;
    Ok(with_common(&metadata, kind, detail_name, stored))
}

/// An existing legacy vault stores logins only.
pub fn require_legacy_item(input: &Value) -> Result<()> {
    match input.as_object().and_then(|object| object.get("type")) {
        None => Ok(()),
        Some(Value::String(kind)) if kind == "login" => Ok(()),
        Some(_) => Err("APIキー・カード・銀行/証券の保存には新しい形式への移行が必要です。保管庫の管理から移行してください".into()),
    }
}

pub fn parse_entry_id(value: &Value) -> Result<String> {
    let id = text(Some(value), "エントリID", ID_BYTES)?;
    if id.is_empty() || id.contains('\0') {
        return Err("エントリIDの形式が正しくありません".into());
    }
    Ok(id.to_string())
}

pub fn parse_group_payload(value: &Value) -> Result<(Vec<String>, Option<String>)> {
    let input = record(Some(value), &["ids", "group"])?;
    let raw_ids = input.get("ids").and_then(Value::as_array).ok_or("対象の項目は配列で指定してください")?;
    if raw_ids.is_empty() {
        return Err("対象の項目を1件以上選んでください".into());
    }
    if raw_ids.len() > MAX_ENTRIES {
        return Err("対象の項目は10000件まで指定できます".into());
    }
    let mut ids: Vec<String> = Vec::with_capacity(raw_ids.len());
    let mut seen = std::collections::HashSet::new();
    for raw in raw_ids {
        let id = parse_entry_id(raw)?;
        if seen.insert(id.clone()) {
            ids.push(id);
        }
    }
    if input.get("group") == Some(&Value::Null) {
        return Ok((ids, None));
    }
    let group = js_trim(text(input.get("group"), "グループ", GROUP_BYTES)?);
    if group.is_empty() {
        return Err("グループ名を入力してください".into());
    }
    if group == UNGROUPED_GROUP_NAME {
        return Err(format!("「{UNGROUPED_GROUP_NAME}」はグループ名に使えません"));
    }
    Ok((ids, Some(group.to_string())))
}

/// `new Date().toISOString()`
pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn canonical_date(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    let parsed = DateTime::parse_from_rfc3339(text).ok()?;
    (parsed.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Millis, true) == text).then_some(text)
}

/// The app authenticates and validates every entry when it unlocks, so one entry it rejects would
/// lock the user out of the whole vault. This runs before a nonce is used, as `serialize` does.
pub fn validate_stored_entry(entry: &Value, expected_id: &str) -> Result<()> {
    let bad = || INVALID_ENTRY.to_string();
    let object = entry.as_object().ok_or_else(bad)?;
    let kind = object.get("type").and_then(Value::as_str);
    let mut fields: Vec<&str> = COMMON_FIELDS.into_iter().chain(["id", "createdAt", "updatedAt"]).collect();
    match kind {
        None if !object.contains_key("type") => fields.extend(["loginId", "password", "passwordChangedAt"]),
        Some("apiKey") => fields.extend(["type", "apiKey"]),
        Some("creditCard") => fields.extend(["type", "card"]),
        Some("financial") => fields.extend(["type", "financial"]),
        _ => return Err(bad()),
    }
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) || entry["id"] != expected_id {
        return Err(bad());
    }
    if kind.is_some() && !(expected_id.len() == 36 && expected_id.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f' | b'-'))) {
        return Err(bad());
    }
    let created = canonical_date(&entry["createdAt"]).ok_or_else(bad)?;
    let updated = canonical_date(&entry["updatedAt"]).ok_or_else(bad)?;
    if created > updated || js_trim(entry["serviceName"].as_str().unwrap_or_default()).is_empty() {
        return Err(bad());
    }
    if kind.is_none() {
        let changed_is_valid = entry["passwordChangedAt"].is_null() || canonical_date(&entry["passwordChangedAt"]).is_some_and(|changed| created <= changed && changed <= updated);
        let required = js_trim(entry["loginId"].as_str().unwrap_or_default()).is_empty() || entry["password"].as_str().unwrap_or_default().is_empty();
        if !changed_is_valid || required {
            return Err(bad());
        }
    }
    Ok(())
}

fn random_below(limit: usize) -> Result<usize> {
    const FAILED: &str = "パスワードを生成できませんでした";
    // Rejection sampling: a plain remainder would make some characters more likely.
    let accepted = 256 - 256 % limit;
    loop {
        let mut byte = [0u8];
        getrandom::fill(&mut byte).map_err(|_| FAILED)?;
        if usize::from(byte[0]) < accepted {
            return Ok(usize::from(byte[0]) % limit);
        }
    }
}

/// Mirrors parseGenerationOptions and generatePassword.
pub fn generate_password(input: &Value) -> Result<Value> {
    const LENGTH_ERROR: &str = "パスワードの長さは12文字以上64文字以下で指定してください";
    const GROUPS: [(&str, &str); 4] = [
        ("includeUppercase", "ABCDEFGHJKLMNPQRSTUVWXYZ"),
        ("includeLowercase", "abcdefghijkmnopqrstuvwxyz"),
        ("includeNumbers", "23456789"),
        ("includeSymbols", "!@#$%^&*()-_=+[]{}?"),
    ];
    let input = record(Some(input), &["length", "includeUppercase", "includeLowercase", "includeNumbers", "includeSymbols"])?;
    let length = match input.get("length") {
        None => 20.0,
        Some(value) => value.as_f64().ok_or(LENGTH_ERROR)?,
    };
    if length.fract() != 0.0 || !(12.0..=64.0).contains(&length) {
        return Err(LENGTH_ERROR.into());
    }
    let mut groups = Vec::new();
    for (field, characters) in GROUPS {
        match input.get(field) {
            None | Some(Value::Bool(true)) => groups.push(characters.as_bytes()),
            Some(Value::Bool(false)) => {}
            Some(_) => return Err("文字種の指定は真偽値で指定してください".into()),
        }
    }
    if groups.is_empty() {
        return Err("少なくとも1つの文字種を有効にしてください".into());
    }
    let combined: Vec<u8> = groups.concat();
    let mut generated = Zeroizing::new(Vec::with_capacity(length as usize));
    for group in &groups {
        generated.push(group[random_below(group.len())?]);
    }
    while generated.len() < length as usize {
        generated.push(combined[random_below(combined.len())?]);
    }
    for index in (1..generated.len()).rev() {
        generated.swap(index, random_below(index + 1)?);
    }
    Ok(json!({ "password": String::from_utf8_lossy(&generated) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Value {
        json!({ "serviceName": " 合成 ", "loginId": " id ", "password": " keep " })
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
        let parsed = parse_vault_entry(&login()).unwrap();
        assert_eq!(parsed["serviceName"], "合成");
        assert_eq!(parsed["loginId"], "id");
        assert_eq!(parsed["password"], " keep ");
        assert_eq!(parsed["group"], Value::Null);
        assert_eq!(parsed["url"], "");
        assert!(parsed.get("type").is_none());
    }

    #[test]
    fn limits_count_utf8_bytes_and_unknown_fields_are_refused() {
        let mut input = login();
        input["password"] = json!("あ".repeat(PASSWORD_BYTES / 3 + 1));
        assert_eq!(parse_login(&input).unwrap_err(), format!("パスワードの容量が上限を超えています（{PASSWORD_BYTES} byteまで）"));
        let mut input = login();
        input["extra"] = json!(1);
        assert_eq!(parse_login(&input).unwrap_err(), "未対応の入力項目があります");
        assert_eq!(parse_login(&json!([])).unwrap_err(), "入力はオブジェクトで指定してください");
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

    #[test]
    fn stored_entries_that_the_app_would_reject_are_caught_first() {
        let id = "11111111-1111-4111-8111-111111111111";
        let now = "2029-01-01T00:00:00.000Z";
        let later = "2029-01-02T00:00:00.000Z";
        let mut entry = parse_vault_entry(&login()).unwrap();
        for (field, value) in [("id", id), ("createdAt", now), ("updatedAt", later), ("passwordChangedAt", later)] {
            entry[field] = json!(value);
        }
        assert_eq!(validate_stored_entry(&entry, id), Ok(()));
        assert!(validate_stored_entry(&entry, "another-id").is_err());
        let change = |field: &str, value: Value| {
            let mut changed = entry.clone();
            changed[field] = value;
            validate_stored_entry(&changed, id)
        };
        assert!(change("createdAt", json!("2030-01-01T00:00:00.000Z")).is_err(), "created after updated");
        assert!(change("updatedAt", json!("2029-01-02T00:00:00Z")).is_err(), "not the canonical form");
        assert!(change("passwordChangedAt", json!("2031-01-01T00:00:00.000Z")).is_err(), "changed after updated");
        assert!(change("passwordChangedAt", Value::Null).is_ok(), "an unknown date stays allowed");
        assert!(change("password", json!("")).is_err());
        assert!(change("unexpected", json!(1)).is_err());
    }

    #[test]
    fn generated_passwords_have_the_length_and_a_character_of_each_kind() {
        for _ in 0..200 {
            let result = generate_password(&json!({ "length": 12 })).unwrap();
            let password = result["password"].as_str().unwrap();
            assert_eq!(password.len(), 12);
            assert!(password.bytes().any(|byte| byte.is_ascii_uppercase()) && password.bytes().any(|byte| byte.is_ascii_lowercase()));
            assert!(password.bytes().any(|byte| byte.is_ascii_digit()) && password.bytes().any(|byte| !byte.is_ascii_alphanumeric()));
        }
        let digits = generate_password(&json!({ "includeUppercase": false, "includeLowercase": false, "includeSymbols": false })).unwrap();
        assert_eq!(digits["password"].as_str().unwrap().len(), 20);
        assert!(digits["password"].as_str().unwrap().bytes().all(|byte| (b'2'..=b'9').contains(&byte)), "ambiguous 0 and 1 stay excluded");
    }

    #[test]
    fn random_choices_are_not_biased_toward_small_values() {
        let mut counts = [0u32; 7];
        for _ in 0..70_000 {
            counts[random_below(7).unwrap()] += 1;
        }
        assert!(counts.iter().all(|count| (9_300..=10_700).contains(count)), "{counts:?}");
    }
}
