use crate::error::{Error, Result};
use crate::keymanager::KeyStore;
use chrono::{Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Unified cost report — normalized across providers.
#[derive(Debug, Clone, Serialize)]
pub struct CostReport {
    pub provider: String,
    pub period_start: String,
    pub period_end: String,
    /// Total cost in cents (USD)
    pub total_cost_cents: f64,
    pub currency: String,
    pub line_items: Vec<CostLineItem>,
}

/// A single line item (e.g. "GPT-4o" or "Claude API").
#[derive(Debug, Clone, Serialize)]
pub struct CostLineItem {
    pub description: String,
    /// Cost in cents (USD)
    pub cost_cents: f64,
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// Simple in-memory cache with TTL (default 1 hour).
struct CacheEntry {
    report: CostReport,
    fetched_at: Instant,
}

/// Thread-safe response cache. Lives for the process lifetime.
pub struct UsageCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl UsageCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    fn get(&self, provider: &str) -> Option<CostReport> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(provider)?;
        if entry.fetched_at.elapsed() < self.ttl {
            Some(entry.report.clone())
        } else {
            None
        }
    }

    fn set(&self, provider: &str, report: CostReport) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                provider.to_string(),
                CacheEntry {
                    report,
                    fetched_at: Instant::now(),
                },
            );
        }
    }
}

impl Default for UsageCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600))
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch cost report for a provider.
///
/// Retrieves the admin key from KeyStore, calls the appropriate API,
/// and returns a normalized CostReport.
pub async fn fetch_cost(
    store: &impl KeyStore,
    provider: &str,
    cache: &UsageCache,
    refresh: bool,
) -> Result<CostReport> {
    // Check cache first (unless --refresh)
    if !refresh
        && let Some(cached) = cache.get(provider)
    {
        return Ok(cached);
    }

    let report = match provider {
        "openai" => fetch_openai_cost(store).await?,
        "anthropic" => fetch_anthropic_cost(store).await?,
        other => {
            return Err(Error::Usage(format!(
                "Unknown provider '{}'. Supported: openai, anthropic",
                other
            )));
        }
    };

    cache.set(provider, report.clone());
    Ok(report)
}

/// List providers that have admin keys registered.
///
/// Returns `Err` if the Keychain is locked or inaccessible (rather than
/// silently treating all errors as "key not found").
pub fn available_providers(store: &impl KeyStore) -> Result<Vec<String>> {
    let mut providers = Vec::new();
    for provider in &["openai", "anthropic"] {
        let admin_key = format!("{}:admin", provider);
        match store.get(&admin_key) {
            Ok(_) => providers.push(provider.to_string()),
            Err(Error::KeyNotFound { .. }) => {} // genuinely absent — skip
            Err(e) => return Err(e),             // Keychain locked, etc. — propagate
        }
    }
    Ok(providers)
}

// ---------------------------------------------------------------------------
// Current billing period
// ---------------------------------------------------------------------------

/// Returns (start_of_month, now) as (NaiveDate, NaiveDate).
fn current_billing_period() -> (NaiveDate, NaiveDate) {
    let today = Utc::now().date_naive();
    let start = NaiveDate::from_ymd_opt(today.year(), today.month(), 1)
        .unwrap_or(today);
    (start, today)
}

// ---------------------------------------------------------------------------
// OpenAI
// ---------------------------------------------------------------------------

/// OpenAI Costs API response (partial).
#[derive(Debug, Deserialize)]
struct OpenAiCostsResponse {
    data: Vec<OpenAiCostBucket>,
}

#[derive(Debug, Deserialize)]
struct OpenAiCostBucket {
    results: Vec<OpenAiCostResult>,
}

#[derive(Debug, Deserialize)]
struct OpenAiCostResult {
    amount: OpenAiAmount,
    #[serde(default)]
    line_item: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenAiAmount {
    value: f64,
    #[serde(default = "default_usd")]
    currency: String,
}

fn default_usd() -> String {
    "usd".to_string()
}

/// Fetch cost from OpenAI `/v1/organization/costs`.
async fn fetch_openai_cost(store: &impl KeyStore) -> Result<CostReport> {
    let admin_key = get_admin_key(store, "openai")?;
    let (start, end) = current_billing_period();

    let start_ts = start
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp();
    let end_ts = end
        .succ_opt()
        .unwrap_or(end)
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp();

    let url = format!(
        "https://api.openai.com/v1/organization/costs?\
         start_time={}&end_time={}&bucket_width=1d&limit=31&group_by=line_item",
        start_ts, end_ts
    );

    let client = http_client();
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", &*admin_key))
        .send()
        .await
        .map_err(|e| Error::Usage(format!("OpenAI API request failed: {}", e)))?;

    // admin_key is Zeroizing<String>; explicit drop zeroes memory before response parsing
    drop(admin_key);

    let resp = check_response(
        resp,
        "OpenAI admin key is invalid or expired. \
         Create a new one at: https://platform.openai.com/settings/organization/admin-keys",
    )
    .await?;

    let body: OpenAiCostsResponse = resp
        .json()
        .await
        .map_err(|e| Error::Usage(format!("Failed to parse OpenAI response: {}", e)))?;

    // Aggregate across all daily buckets
    let mut line_item_costs: HashMap<String, f64> = HashMap::new();
    for bucket in &body.data {
        for result in &bucket.results {
            let desc = result
                .line_item
                .clone()
                .unwrap_or_else(|| "Other".to_string());
            // OpenAI returns float USD — convert to cents
            *line_item_costs.entry(desc).or_default() += result.amount.value * 100.0;
        }
    }

    let line_items: Vec<CostLineItem> = {
        let mut items: Vec<_> = line_item_costs
            .into_iter()
            .map(|(description, cost_cents)| CostLineItem {
                description,
                cost_cents: cost_cents.round(),
            })
            .collect();
        sort_by_cost_desc(&mut items);
        items
    };

    let total_cost_cents = line_items.iter().map(|i| i.cost_cents).sum();

    Ok(CostReport {
        provider: "openai".to_string(),
        period_start: start.to_string(),
        period_end: end.to_string(),
        total_cost_cents,
        currency: "usd".to_string(),
        line_items,
    })
}

// ---------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------

/// Anthropic Cost Report response (partial).
#[derive(Debug, Deserialize)]
struct AnthropicCostResponse {
    data: Vec<AnthropicCostResult>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AnthropicCostResult {
    #[serde(default)]
    description: Option<String>,
    /// Cost in cents as a decimal string (e.g. "1350" = $13.50)
    amount: String,
    #[serde(default = "default_usd")]
    currency: String,
}

/// Fetch cost from Anthropic `/v1/organizations/cost_report`.
async fn fetch_anthropic_cost(store: &impl KeyStore) -> Result<CostReport> {
    let admin_key = get_admin_key(store, "anthropic")?;
    let (start, end) = current_billing_period();

    let start_iso = format!("{}T00:00:00Z", start);
    let end_iso = format!(
        "{}T00:00:00Z",
        end.succ_opt().unwrap_or(end)
    );

    let url = format!(
        "https://api.anthropic.com/v1/organizations/cost_report?\
         starting_at={}&ending_at={}&group_by[]=description",
        start_iso, end_iso
    );

    let client = http_client();
    let resp = client
        .get(&url)
        .header("x-api-key", &*admin_key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
        .map_err(|e| Error::Usage(format!("Anthropic API request failed: {}", e)))?;

    drop(admin_key);

    let resp = check_response(
        resp,
        "Anthropic admin key is invalid or requires an Organization account.\n  \
         Individual accounts cannot use the Usage API.\n  \
         View your usage at: https://console.anthropic.com/settings/billing",
    )
    .await?;

    let body: AnthropicCostResponse = resp
        .json()
        .await
        .map_err(|e| Error::Usage(format!("Failed to parse Anthropic response: {}", e)))?;

    let line_items: Vec<CostLineItem> = {
        let mut items: Vec<_> = body
            .data
            .iter()
            .map(|r| CostLineItem {
                description: r
                    .description
                    .clone()
                    .unwrap_or_else(|| "Claude API".to_string()),
                cost_cents: r.amount.parse::<f64>().unwrap_or(0.0),
            })
            .collect();
        sort_by_cost_desc(&mut items);
        items
    };

    let total_cost_cents = line_items.iter().map(|i| i.cost_cents).sum();

    Ok(CostReport {
        provider: "anthropic".to_string(),
        period_start: start.to_string(),
        period_end: end.to_string(),
        total_cost_cents,
        currency: "usd".to_string(),
        line_items,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// HTTP client with a 30-second timeout — prevents CLI hangs on stalled APIs.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Check HTTP response status, returning a typed error for auth failures.
async fn check_response(resp: reqwest::Response, auth_error_msg: &str) -> Result<reqwest::Response> {
    let status = resp.status().as_u16();
    if status == 401 || status == 403 {
        return Err(Error::Usage(auth_error_msg.to_string()));
    }
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::HttpError { status, body });
    }
    Ok(resp)
}

/// Sort cost line items by cost descending.
fn sort_by_cost_desc(items: &mut Vec<CostLineItem>) {
    items.sort_by(|a, b| {
        b.cost_cents
            .partial_cmp(&a.cost_cents)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

/// Retrieve the admin key for a provider from KeyStore.
fn get_admin_key(
    store: &impl KeyStore,
    provider: &str,
) -> Result<zeroize::Zeroizing<String>> {
    let key_name = format!("{}:admin", provider);
    match store.get(&key_name) {
        Ok((value, kind)) => {
            if kind != crate::keymanager::KeyKind::Admin {
                return Err(Error::Usage(format!(
                    "Key '{}' is not an admin key. Re-register with `lkr set {} --kind admin`.",
                    key_name, key_name
                )));
            }
            Ok(value)
        }
        Err(Error::KeyNotFound { .. }) => Err(Error::AdminKeyRequired {
            provider: provider.to_string(),
        }),
        Err(e) => Err(e),
    }
}

/// Format cents as dollar string (e.g. 1350.0 → "$13.50").
pub fn format_cost(cents: f64) -> String {
    if !cents.is_finite() {
        return "$-.--".to_string();
    }
    format!("${:.2}", cents / 100.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keymanager::{KeyKind, MockStore};

    #[test]
    fn test_format_cost() {
        assert_eq!(format_cost(0.0), "$0.00");
        assert_eq!(format_cost(1350.0), "$13.50");
        assert_eq!(format_cost(42.0), "$0.42");
        assert_eq!(format_cost(10000.0), "$100.00");
    }

    #[test]
    fn test_available_providers_empty() {
        let store = MockStore::new();
        assert!(available_providers(&store).unwrap().is_empty());
    }

    #[test]
    fn test_available_providers_with_admin_keys() {
        let store = MockStore::new();
        store
            .set("openai:admin", "sk-admin-test", KeyKind::Admin, false)
            .unwrap();
        let providers = available_providers(&store).unwrap();
        assert_eq!(providers, vec!["openai"]);
    }

    #[test]
    fn test_get_admin_key_not_found() {
        let store = MockStore::new();
        let err = get_admin_key(&store, "openai").unwrap_err();
        assert!(matches!(err, Error::AdminKeyRequired { .. }));
    }

    #[test]
    fn test_get_admin_key_wrong_kind() {
        let store = MockStore::new();
        store
            .set("openai:admin", "sk-admin-test", KeyKind::Runtime, false)
            .unwrap();
        let err = get_admin_key(&store, "openai").unwrap_err();
        assert!(matches!(err, Error::Usage(_)));
    }

    #[test]
    fn test_get_admin_key_success() {
        let store = MockStore::new();
        store
            .set("openai:admin", "sk-admin-test", KeyKind::Admin, false)
            .unwrap();
        let key = get_admin_key(&store, "openai").unwrap();
        assert_eq!(&*key, "sk-admin-test");
    }

    #[test]
    fn test_cache_hit_and_miss() {
        let cache = UsageCache::new(Duration::from_secs(3600));
        assert!(cache.get("openai").is_none());

        let report = CostReport {
            provider: "openai".to_string(),
            period_start: "2026-02-01".to_string(),
            period_end: "2026-02-27".to_string(),
            total_cost_cents: 1350.0,
            currency: "usd".to_string(),
            line_items: vec![],
        };
        cache.set("openai", report);
        assert!(cache.get("openai").is_some());
        assert!(cache.get("anthropic").is_none());
    }

    #[test]
    fn test_cache_expiry() {
        let cache = UsageCache::new(Duration::from_millis(1));
        let report = CostReport {
            provider: "openai".to_string(),
            period_start: "2026-02-01".to_string(),
            period_end: "2026-02-27".to_string(),
            total_cost_cents: 0.0,
            currency: "usd".to_string(),
            line_items: vec![],
        };
        cache.set("openai", report);
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("openai").is_none());
    }

    #[tokio::test]
    async fn test_fetch_cost_unknown_provider() {
        let store = MockStore::new();
        let cache = UsageCache::default();
        let err = fetch_cost(&store, "unknown", &cache, false).await.unwrap_err();
        assert!(matches!(err, Error::Usage(_)));
    }

    #[tokio::test]
    async fn test_fetch_cost_missing_admin_key() {
        let store = MockStore::new();
        let cache = UsageCache::default();
        let err = fetch_cost(&store, "openai", &cache, false).await.unwrap_err();
        assert!(matches!(err, Error::AdminKeyRequired { .. }));
    }

    #[test]
    fn test_current_billing_period() {
        let (start, end) = current_billing_period();
        assert_eq!(start.day(), 1);
        assert!(end >= start);
    }
}
