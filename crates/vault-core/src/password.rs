//! Password generation, following apps/api/src/services/password-service.ts and
//! parseGenerationOptions. Ambiguous characters such as 0, O, 1 and l stay excluded.

use crate::error::{Result, VaultError};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const LENGTH_ERROR: &str = "パスワードの長さは12文字以上64文字以下で指定してください";
const GROUPS: [(&str, &str); 4] = [
    ("includeUppercase", "ABCDEFGHJKLMNPQRSTUVWXYZ"),
    ("includeLowercase", "abcdefghijkmnopqrstuvwxyz"),
    ("includeNumbers", "23456789"),
    ("includeSymbols", "!@#$%^&*()-_=+[]{}?"),
];

fn random_below(limit: usize) -> Result<usize> {
    // Rejection sampling: a plain remainder would make some characters more likely.
    let accepted = 256 - 256 % limit;
    loop {
        let mut byte = [0u8];
        getrandom::fill(&mut byte).map_err(|_| VaultError::new(500, "パスワードを生成できませんでした"))?;
        if usize::from(byte[0]) < accepted {
            return Ok(usize::from(byte[0]) % limit);
        }
    }
}

/// `options` is the argument the screen sent; a missing one means the defaults, as in the app.
pub fn generate_password(options: Option<&Value>) -> Result<Value> {
    let default = json!({});
    let input = options.unwrap_or(&default).as_object().ok_or_else(|| VaultError::bad_request("入力はオブジェクトで指定してください"))?;
    if !input.keys().all(|key| key == "length" || GROUPS.iter().any(|(field, _)| field == key)) {
        return Err(VaultError::bad_request("未対応の入力項目があります"));
    }
    let length = match input.get("length") {
        None => 20.0,
        Some(value) => value.as_f64().ok_or_else(|| VaultError::bad_request(LENGTH_ERROR))?,
    };
    if length.fract() != 0.0 || !(12.0..=64.0).contains(&length) {
        return Err(VaultError::bad_request(LENGTH_ERROR));
    }
    let mut groups = Vec::new();
    for (field, characters) in GROUPS {
        match input.get(field) {
            None | Some(Value::Bool(true)) => groups.push(characters.as_bytes()),
            Some(Value::Bool(false)) => {}
            Some(_) => return Err(VaultError::bad_request("文字種の指定は真偽値で指定してください")),
        }
    }
    if groups.is_empty() {
        return Err(VaultError::bad_request("少なくとも1つの文字種を有効にしてください"));
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

    #[test]
    fn generated_passwords_have_the_length_and_a_character_of_each_kind() {
        for _ in 0..200 {
            let result = generate_password(Some(&json!({ "length": 12 }))).unwrap();
            let password = result["password"].as_str().unwrap();
            assert_eq!(password.len(), 12);
            assert!(password.bytes().any(|byte| byte.is_ascii_uppercase()) && password.bytes().any(|byte| byte.is_ascii_lowercase()));
            assert!(password.bytes().any(|byte| byte.is_ascii_digit()) && password.bytes().any(|byte| !byte.is_ascii_alphanumeric()));
        }
        assert_eq!(generate_password(None).unwrap()["password"].as_str().unwrap().len(), 20);
        let digits = generate_password(Some(&json!({ "includeUppercase": false, "includeLowercase": false, "includeSymbols": false }))).unwrap();
        assert!(digits["password"].as_str().unwrap().bytes().all(|byte| (b'2'..=b'9').contains(&byte)), "ambiguous 0 and 1 stay excluded");
    }

    #[test]
    fn options_are_checked_like_the_app() {
        let refused = |options: Value| generate_password(Some(&options)).unwrap_err().message;
        assert_eq!(refused(json!({ "length": 11 })), LENGTH_ERROR);
        assert_eq!(refused(json!({ "length": 12.5 })), LENGTH_ERROR);
        assert_eq!(refused(json!({ "length": "20" })), LENGTH_ERROR);
        assert_eq!(refused(json!({ "includeNumbers": 1 })), "文字種の指定は真偽値で指定してください");
        assert_eq!(refused(json!({ "includeUppercase": false, "includeLowercase": false, "includeNumbers": false, "includeSymbols": false })), "少なくとも1つの文字種を有効にしてください");
        assert_eq!(refused(json!({ "other": true })), "未対応の入力項目があります");
        assert_eq!(refused(Value::Null), "入力はオブジェクトで指定してください");
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
