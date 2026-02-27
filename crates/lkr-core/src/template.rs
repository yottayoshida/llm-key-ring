use crate::error::{Error, Result};
use crate::keymanager::KeyStore;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

// ---------------------------------------------------------------------------
// Template types
// ---------------------------------------------------------------------------

/// A resolved placeholder — either matched to a Keychain key or left unresolved.
#[derive(Debug)]
pub struct Resolution {
    /// Original variable or placeholder name (e.g. "OPENAI_API_KEY" or "{{lkr:openai:prod}}")
    pub placeholder: String,
    /// Resolved Keychain key name, if found (e.g. "openai:prod")
    pub key_name: Option<String>,
    /// Other keys for the same provider (for disambiguation warnings)
    pub alternatives: Vec<String>,
}

/// Result of template generation: the rendered content + resolution details.
#[derive(Debug)]
pub struct GenResult {
    /// Rendered file content (keys injected)
    pub content: String,
    /// Details of each resolved/unresolved placeholder
    pub resolutions: Vec<Resolution>,
}

// ---------------------------------------------------------------------------
// Known provider mappings for .env auto-detection
// ---------------------------------------------------------------------------

/// Maps common env var prefixes to LKR provider names.
/// Used by .env.example auto-detection: `OPENAI_API_KEY` → tries `openai:*`.
const ENV_PREFIX_MAP: &[(&str, &str)] = &[
    ("OPENAI_", "openai"),
    ("ANTHROPIC_", "anthropic"),
    ("GOOGLE_", "google"),
    ("MISTRAL_", "mistral"),
    ("COHERE_", "cohere"),
    ("GROQ_", "groq"),
    ("PERPLEXITY_", "perplexity"),
    ("FIREWORKS_", "fireworks"),
    ("TOGETHER_", "together"),
    ("REPLICATE_", "replicate"),
    ("HUGGINGFACE_", "huggingface"),
    ("DEEPSEEK_", "deepseek"),
    ("XAI_", "xai"),
    ("AZURE_OPENAI_", "azure-openai"),
    ("AWS_", "aws"),
    ("VOYAGE_", "voyage"),
    ("ANYSCALE_", "anyscale"),
];

/// Map a key name (e.g. `openai:prod`) to a conventional env var name
/// (e.g. `OPENAI_API_KEY`).  Returns `None` if the provider is not in
/// `ENV_PREFIX_MAP`.
pub fn key_to_env_var(key_name: &str) -> Option<String> {
    let provider = key_name.split(':').next()?;
    for &(prefix, prov) in ENV_PREFIX_MAP {
        if prov == provider {
            return Some(format!("{}API_KEY", prefix));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate output from a template file, resolving Keychain keys.
///
/// Supports two formats:
/// - `.env.example` style: auto-detects provider from variable names
/// - JSON with `{{lkr:provider:label}}` placeholders
///
/// Admin keys are never resolved (security policy).
pub fn generate(
    store: &impl KeyStore,
    template_path: &Path,
    output_path: &Path,
) -> Result<GenResult> {
    let content = fs::read_to_string(template_path).map_err(|e| {
        Error::Template(format!(
            "Cannot read template '{}': {}",
            template_path.display(),
            e
        ))
    })?;

    // Detect format from content or extension
    let result = if is_json_template(&content) {
        generate_json(store, &content)?
    } else {
        generate_env(store, &content)?
    };

    // Atomic write: write to temp file, then rename
    write_secure(output_path, &result.content)?;

    Ok(result)
}

/// Check if a path is covered by .gitignore (best-effort).
/// Returns `None` if not in a git repository or git is unavailable.
/// Returns `Some(true)` if gitignored, `Some(false)` if not.
pub fn check_gitignore(path: &Path) -> Option<bool> {
    let output = std::process::Command::new("git")
        .args(["check-ignore", "-q"])
        .arg(path)
        .output()
        .ok()?;
    // exit 128 = not a git repo; treat as "not applicable"
    if output.status.code() == Some(128) {
        return None;
    }
    Some(output.status.success())
}

// ---------------------------------------------------------------------------
// .env.example format
// ---------------------------------------------------------------------------

/// Generate from .env.example format.
///
/// Lines like `OPENAI_API_KEY=your-key-here` are auto-resolved by:
/// 1. Matching env var prefix to provider (OPENAI_ → openai)
/// 2. Searching Keychain for any key with that provider
///
/// Lines without `=` or starting with `#` are passed through.
fn generate_env(store: &impl KeyStore, content: &str) -> Result<GenResult> {
    // Get available keys (runtime only — admin keys excluded)
    let entries = store.list(false)?;
    let provider_map = build_provider_map(&entries);

    let mut output = String::new();
    let mut resolutions = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Pass through comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            output.push_str(line);
            output.push('\n');
            continue;
        }

        // Parse KEY=VALUE
        if let Some(eq_pos) = trimmed.find('=') {
            let var_name = trimmed[..eq_pos].trim();

            // Try to resolve from Keychain
            if let Some((key_name, value, alternatives)) = resolve_env_var(store, var_name, &provider_map) {
                output.push_str(&format!("{}={}\n", var_name, &*value));
                resolutions.push(Resolution {
                    placeholder: var_name.to_string(),
                    key_name: Some(key_name),
                    alternatives,
                });
            } else {
                // Keep original line (unresolved)
                output.push_str(line);
                output.push('\n');
                resolutions.push(Resolution {
                    placeholder: var_name.to_string(),
                    key_name: None,
                    alternatives: vec![],
                });
            }
        } else {
            // Not a key=value line, pass through
            output.push_str(line);
            output.push('\n');
        }
    }

    Ok(GenResult {
        content: output,
        resolutions,
    })
}

/// Build a map of provider → (first matching key name, all key names for this provider).
/// Entries are sorted alphabetically, so the first key per provider is deterministic.
fn build_provider_map(
    entries: &[crate::keymanager::KeyEntry],
) -> BTreeMap<String, (String, Vec<String>)> {
    let mut map: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for entry in entries {
        map.entry(entry.provider.clone())
            .and_modify(|(_, alternatives)| alternatives.push(entry.name.clone()))
            .or_insert_with(|| (entry.name.clone(), vec![entry.name.clone()]));
    }
    map
}

/// Try to resolve an env var name to a Keychain key.
/// Returns (key_name, decrypted_value, alternatives) if found.
fn resolve_env_var(
    store: &impl KeyStore,
    var_name: &str,
    provider_map: &BTreeMap<String, (String, Vec<String>)>,
) -> Option<(String, zeroize::Zeroizing<String>, Vec<String>)> {
    let var_upper = var_name.to_uppercase();

    // Match by known prefix
    for &(prefix, provider) in ENV_PREFIX_MAP {
        if var_upper.starts_with(prefix)
            && let Some((key_name, alternatives)) = provider_map.get(provider)
            && let Ok((value, _)) = store.get(key_name)
        {
            return Some((key_name.clone(), value, alternatives.clone()));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// JSON / {{lkr:...}} format
// ---------------------------------------------------------------------------

/// Generate from JSON template with {{lkr:provider:label}} placeholders.
fn generate_json(store: &impl KeyStore, content: &str) -> Result<GenResult> {
    let mut output = content.to_string();
    let mut resolutions = Vec::new();

    // Find all {{lkr:...}} placeholders
    let mut search_from = 0;
    while let Some(pos) = output[search_from..].find("{{lkr:") {
        let start = search_from + pos;
        let end = match output[start..].find("}}") {
            Some(pos) => start + pos + 2,
            None => {
                return Err(Error::Template(format!(
                    "Unclosed placeholder starting at position {}",
                    start
                )));
            }
        };

        // Clone placeholder and key_name before mutating output
        let placeholder = output[start..end].to_string();
        // Extract key name: {{lkr:openai:prod}} → openai:prod
        let key_name = placeholder[6..placeholder.len() - 2].to_string();

        match store.get(&key_name) {
            Ok((value, kind)) => {
                // Security: never resolve admin keys in templates
                if kind == crate::keymanager::KeyKind::Admin {
                    return Err(Error::Template(format!(
                        "Admin key '{}' cannot be used in templates. Only runtime keys are allowed.",
                        key_name
                    )));
                }
                output = format!(
                    "{}{}{}",
                    &output[..start],
                    &*value,
                    &output[end..]
                );
                resolutions.push(Resolution {
                    placeholder,
                    key_name: Some(key_name),
                    alternatives: vec![], // JSON placeholders are explicit; no ambiguity
                });
                // Don't advance search_from past end — replacement may be shorter
                search_from = start + value.len();
            }
            Err(Error::KeyNotFound { .. }) => {
                resolutions.push(Resolution {
                    placeholder,
                    key_name: None,
                    alternatives: vec![],
                });
                search_from = end;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(GenResult {
        content: output,
        resolutions,
    })
}

/// Detect if content looks like a JSON template (contains {{lkr:...}}).
fn is_json_template(content: &str) -> bool {
    content.contains("{{lkr:")
}

// ---------------------------------------------------------------------------
// Secure file writing
// ---------------------------------------------------------------------------

/// Write content to file with 0600 permissions (owner read/write only).
/// Uses temp file + rename for atomicity.
fn write_secure(path: &Path, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));

    // Write to temp file first
    let tmp_path = parent.join(format!(
        ".lkr-gen-{}.tmp",
        std::process::id()
    ));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| Error::Template(format!("Cannot write to '{}': {}", tmp_path.display(), e)))?;

    file.write_all(content.as_bytes())
        .map_err(|e| Error::Template(format!("Write failed: {}", e)))?;
    file.flush()
        .map_err(|e| Error::Template(format!("Flush failed: {}", e)))?;

    // Atomic rename
    fs::rename(&tmp_path, path).map_err(|e| {
        // Clean up temp file on failure
        let _ = fs::remove_file(&tmp_path);
        Error::Template(format!(
            "Cannot rename to '{}': {}",
            path.display(),
            e
        ))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keymanager::{KeyKind, MockStore};

    fn setup_store() -> MockStore {
        let store = MockStore::new();
        store
            .set("openai:prod", "sk-test-openai-key-12345678", KeyKind::Runtime, false)
            .unwrap();
        store
            .set("anthropic:main", "sk-ant-test-key-87654321", KeyKind::Runtime, false)
            .unwrap();
        store
    }

    // -- .env format --

    #[test]
    fn test_env_resolves_known_providers() {
        let store = setup_store();
        let template = "\
# My config
OPENAI_API_KEY=your-key-here
ANTHROPIC_API_KEY=change-me
DATABASE_URL=postgres://localhost/mydb
";
        let result = generate_env(&store, template).unwrap();

        assert!(result.content.contains("OPENAI_API_KEY=sk-test-openai-key-12345678"));
        assert!(result.content.contains("ANTHROPIC_API_KEY=sk-ant-test-key-87654321"));
        assert!(result.content.contains("DATABASE_URL=postgres://localhost/mydb"));
        assert!(result.content.contains("# My config"));

        assert_eq!(result.resolutions.len(), 3);
        assert!(result.resolutions[0].key_name.is_some());
        assert!(result.resolutions[1].key_name.is_some());
        assert!(result.resolutions[2].key_name.is_none());
    }

    #[test]
    fn test_env_preserves_comments_and_blanks() {
        let store = setup_store();
        let template = "# Comment\n\n# Another\nFOO=bar\n";
        let result = generate_env(&store, template).unwrap();

        assert_eq!(result.content, "# Comment\n\n# Another\nFOO=bar\n");
    }

    #[test]
    fn test_env_unresolved_kept_as_is() {
        let store = setup_store();
        let template = "UNKNOWN_KEY=placeholder\n";
        let result = generate_env(&store, template).unwrap();

        assert_eq!(result.content, "UNKNOWN_KEY=placeholder\n");
        assert!(result.resolutions[0].key_name.is_none());
    }

    // -- JSON / {{lkr:...}} format --

    #[test]
    fn test_json_resolves_placeholders() {
        let store = setup_store();
        let template = r#"{
  "mcpServers": {
    "codex": {
      "env": {
        "OPENAI_API_KEY": "{{lkr:openai:prod}}"
      }
    }
  }
}"#;
        let result = generate_json(&store, template).unwrap();

        assert!(result.content.contains("\"OPENAI_API_KEY\": \"sk-test-openai-key-12345678\""));
        assert!(!result.content.contains("{{lkr:"));
        assert_eq!(result.resolutions.len(), 1);
        assert_eq!(
            result.resolutions[0].key_name.as_deref(),
            Some("openai:prod")
        );
    }

    #[test]
    fn test_json_multiple_placeholders() {
        let store = setup_store();
        let template = r#"{"a": "{{lkr:openai:prod}}", "b": "{{lkr:anthropic:main}}"}"#;
        let result = generate_json(&store, template).unwrap();

        assert!(result.content.contains("sk-test-openai-key-12345678"));
        assert!(result.content.contains("sk-ant-test-key-87654321"));
        assert_eq!(result.resolutions.len(), 2);
    }

    #[test]
    fn test_json_unresolved_placeholder_kept() {
        let store = setup_store();
        let template = r#"{"key": "{{lkr:unknown:key}}"}"#;
        let result = generate_json(&store, template).unwrap();

        assert!(result.content.contains("{{lkr:unknown:key}}"));
        assert!(result.resolutions[0].key_name.is_none());
    }

    #[test]
    fn test_json_unclosed_placeholder_error() {
        let store = setup_store();
        let template = r#"{"key": "{{lkr:openai:prod"}"#;
        let err = generate_json(&store, template).unwrap_err();
        assert!(matches!(err, Error::Template(_)));
    }

    #[test]
    fn test_json_admin_key_rejected() {
        let store = MockStore::new();
        store
            .set("openai:admin", "sk-admin-secret", KeyKind::Admin, false)
            .unwrap();
        let template = r#"{"key": "{{lkr:openai:admin}}"}"#;
        let err = generate_json(&store, template).unwrap_err();
        assert!(matches!(err, Error::Template(_)));
    }

    // -- Format detection --

    #[test]
    fn test_is_json_template() {
        assert!(is_json_template(r#"{"key": "{{lkr:openai:prod}}"}"#));
        assert!(!is_json_template("OPENAI_API_KEY=value"));
    }

    // -- Secure writing --

    #[test]
    fn test_write_secure_permissions() {
        let dir = std::env::temp_dir().join("lkr-test-write");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test-output.env");

        write_secure(&path, "SECRET=value\n").unwrap();

        let metadata = fs::metadata(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        // Clean up
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
