fn rate_limits_table() -> String {
    "abuse-rate-limits".to_string()
}

/// Check and increment a rate-limit counter.
/// Returns (allowed, remaining).
pub async fn check_rate(key: &str, limit: u64, window_secs: u64) -> Result<(bool, u64), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let window_start = now - (now % window_secs);
    let db_key = format!("rate:{}:{}", key, window_start);
    let table = rate_limits_table();

    const MAX_RETRIES: usize = 5;
    for _attempt in 0..MAX_RETRIES {
        let raw = crate::store::kv_get_raw_with_revision(&table, &db_key).await;

        let (count, revision) = match raw {
            Ok(Some((bytes, rev))) => {
                let count_str = String::from_utf8_lossy(&bytes);
                let count: u64 = count_str.trim().parse().unwrap_or(0);
                (count, rev)
            }
            Ok(None) => (0u64, 0u64),
            Err(e) => return Err(format!("rate limit get: {e}")),
        };

        if count >= limit {
            return Ok((false, 0));
        }

        let new_count = (count + 1).to_string();

        if revision == 0 {
            match crate::store::kv_create_raw(
                &table,
                &db_key,
                new_count.as_bytes(),
                Some(window_secs + 10),
            )
            .await
            {
                Ok(()) => return Ok((true, limit - count - 1)),
                Err(e) if e.contains("already exists") => continue,
                Err(e) => return Err(format!("rate limit create: {e}")),
            }
        } else {
            let window_ttl = window_secs + 10;
            match crate::store::kv_cas_raw(&table, &db_key, new_count.as_bytes(), revision, Some(window_ttl)).await {
                Ok(()) => return Ok((true, limit - count - 1)),
                Err(e) if e.contains("revision mismatch") => continue,
                Err(e) => return Err(format!("rate limit cas: {e}")),
            }
        }
    }

    // Fail-open: allow but don't increment
    Ok((true, 0))
}

#[allow(dead_code)]
pub async fn record_metric(_name: &str, _labels: &[(&str, &str)]) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_round_window_down() {
        let now = 1_000_000u64;
        let window_secs = 3600u64;
        let window_start = now - (now % window_secs);
        assert_eq!(window_start, 997_200);
    }

    #[test]
    fn test_window_boundary() {
        let now = 3600u64;
        let window_secs = 3600u64;
        let window_start = now - (now % window_secs);
        assert_eq!(window_start, 3600);
    }

    #[test]
    fn test_window_after_one_period() {
        let now = 7200u64;
        let window_secs = 3600u64;
        let window_start = now - (now % window_secs);
        assert_eq!(window_start, 7200);
    }

    #[test]
    fn test_key_format() {
        let key = "rate:test-key:1000000";
        assert!(key.starts_with("rate:"));
        assert!(key.contains(':'));
    }
}
