//! The password audit, following apps/api/src/services/audit-service.ts. Strength comes from the
//! `zxcvbn` crate rather than zxcvbn-ts: both put about 99.5% of passwords on the same side of
//! "weak", but the crate lacks zxcvbn-ts's date and word-sequence patterns and reads only the first
//! 100 characters, so a few passwords that the app calls weak pass here (docs/設計.md lists this).
//! Everything else is counted as the app counts it, and the result never carries a password.

use crate::error::Result;
use crate::input::js_trim;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::collections::HashMap;
use zeroize::Zeroizing;

const YEAR_MS: i64 = 365 * 86_400_000;
/// The lowest zxcvbn score that is not weak.
const STRONG_ENOUGH: u8 = 3;
const ISSUES: [&str; 5] = ["weak", "duplicate", "oldPassword", "missingUrl", "staleEntry"];

/// One login as the audit reads it.
pub struct Row {
    pub id: String,
    pub service_name: String,
    pub login_id: String,
    pub password: Zeroizing<String>,
    pub url: Option<String>,
    pub updated_at: String,
    pub password_changed_at: Option<String>,
}

/// Date.parse for the ISO dates the app writes. Anything else is NaN there, which no check passes.
fn parse_time(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text).ok().map(|time| time.timestamp_millis())
}

fn older_than_a_year(text: &str, now: i64) -> bool {
    parse_time(text).is_some_and(|time| now - time >= YEAR_MS)
}

fn is_weak(row: &Row) -> bool {
    (zxcvbn::zxcvbn(&row.password, &[&row.service_name, &row.login_id]).score() as u8) < STRONG_ENOUGH
}

/// Scores the rows at `now` (milliseconds since 1970). `checkpoint` runs before every eighth row,
/// where the app pauses and confirms that the same session still holds the vault.
pub fn assess(rows: &[Row], now: i64, mut checkpoint: impl FnMut() -> Result<()>) -> Result<Value> {
    let mut frequency: HashMap<&str, usize> = HashMap::new();
    for row in rows {
        *frequency.entry(row.password.as_str()).or_default() += 1;
    }
    let mut counts = [0usize; ISSUES.len()];
    let mut unknown_password_age = 0;
    let mut items = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if index % 8 == 0 {
            checkpoint()?;
        }
        let mut issues = Vec::new();
        if is_weak(row) {
            issues.push(0);
        }
        if frequency[row.password.as_str()] > 1 {
            issues.push(1);
        }
        match row.password_changed_at.as_deref() {
            None => unknown_password_age += 1,
            Some(changed) if older_than_a_year(changed, now) => issues.push(2),
            Some(_) => {}
        }
        if row.url.as_deref().is_none_or(|url| js_trim(url).is_empty()) {
            issues.push(3);
        }
        if older_than_a_year(&row.updated_at, now) {
            issues.push(4);
        }
        for &issue in &issues {
            counts[issue] += 1;
        }
        if !issues.is_empty() {
            let issues: Vec<&str> = issues.iter().map(|&issue| ISSUES[issue]).collect();
            items.push(json!({ "id": row.id, "serviceName": row.service_name, "loginId": row.login_id, "issues": issues }));
        }
    }
    // Each entry contributes 60 points for strength and 40 for uniqueness. The value is never
    // negative, where Math.round and f64::round would differ.
    let score = (!rows.is_empty()).then(|| (100.0 - (60 * counts[0] + 40 * counts[1]) as f64 / rows.len() as f64).round() as i64);
    let checked_at = DateTime::<Utc>::from_timestamp_millis(now).unwrap_or_default().to_rfc3339_opts(SecondsFormat::Millis, true);
    let counts: serde_json::Map<String, Value> = ISSUES.iter().zip(counts).map(|(issue, count)| (issue.to_string(), json!(count))).collect();
    Ok(json!({ "score": score, "total": rows.len(), "checkedAt": checked_at, "unknownPasswordAgeCount": unknown_password_age, "counts": counts, "items": items }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::VaultError;

    const NOW: i64 = 1_793_923_200_000; // 2026-11-06T00:00:00.000Z

    fn row(id: &str, password: &str, url: Option<&str>, updated_at: &str, changed: Option<&str>) -> Row {
        Row {
            id: id.to_string(),
            service_name: format!("Service {id}"),
            login_id: "user".to_string(),
            password: Zeroizing::new(password.to_string()),
            url: url.map(str::to_string),
            updated_at: updated_at.to_string(),
            password_changed_at: changed.map(str::to_string),
        }
    }

    #[test]
    fn each_issue_is_counted_as_the_app_counts_it() {
        let recent = "2026-10-01T00:00:00.000Z";
        let old = "2025-11-06T00:00:00.000Z"; // exactly 365 days earlier counts as old
        let rows = [
            row("a", "password1", Some("https://example.test/"), recent, Some(recent)),
            row("b", "synthetic-shared-audit-password", Some(" \u{feff}\u{3000}"), recent, Some(old)),
            row("c", "synthetic-shared-audit-password", None, old, None),
            row("d", "kV9#mP2$wL7!qR4zT8", Some("https://example.test/"), "not a date", Some("not a date")),
        ];
        let result = assess(&rows, NOW, || Ok(())).unwrap();
        assert_eq!(result["score"], json!(65)); // 100 - (60 * 1 + 40 * 2) / 4
        assert_eq!(result["total"], json!(4));
        assert_eq!(result["checkedAt"], json!("2026-11-06T00:00:00.000Z"));
        assert_eq!(result["unknownPasswordAgeCount"], json!(1));
        assert_eq!(result["counts"], json!({ "weak": 1, "duplicate": 2, "oldPassword": 1, "missingUrl": 2, "staleEntry": 1 }));
        assert_eq!(
            result["items"],
            json!([
                { "id": "a", "serviceName": "Service a", "loginId": "user", "issues": ["weak"] },
                { "id": "b", "serviceName": "Service b", "loginId": "user", "issues": ["duplicate", "oldPassword", "missingUrl"] },
                { "id": "c", "serviceName": "Service c", "loginId": "user", "issues": ["duplicate", "missingUrl", "staleEntry"] }
            ])
        );
        assert!(!result.to_string().contains("synthetic-shared"), "the result never carries a password");
    }

    #[test]
    fn an_empty_vault_has_no_score_and_the_session_is_checked_every_eighth_entry() {
        assert_eq!(assess(&[], NOW, || Ok(())).unwrap()["score"], Value::Null);
        let rows: Vec<Row> = (0..17).map(|index| row(&index.to_string(), "kV9#mP2$wL7!qR4zT8", Some("x"), "2026-10-01T00:00:00.000Z", None)).collect();
        let mut checks = 0;
        assess(&rows, NOW, || {
            checks += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(checks, 3);
        let stopped = assess(&rows, NOW, || Err(VaultError::conflict("changed")));
        assert_eq!(stopped.err(), Some(VaultError::conflict("changed")));
    }
}
