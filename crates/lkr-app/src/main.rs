// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use lkr_core::{KeyKind, KeyStore, KeychainStore};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct GetKeyResponse {
    name: String,
    masked_value: String,
    kind: String,
}

#[derive(Deserialize)]
struct SetKeyRequest {
    name: String,
    value: String,
    kind: String,
    force: bool,
}

#[tauri::command]
fn get_key(name: String) -> Result<GetKeyResponse, String> {
    let store = KeychainStore::new();
    let (value, kind) = store.get(&name).map_err(|e| e.to_string())?;
    Ok(GetKeyResponse {
        name,
        masked_value: mask_value(&value),
        kind: kind.to_string(),
    })
}

fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 8 {
        return "*".repeat(len);
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[len - 4..].iter().collect();
    format!("{}...{}", prefix, suffix)
}

#[tauri::command]
fn set_key(req: SetKeyRequest) -> Result<String, String> {
    let store = KeychainStore::new();
    let kind = match req.kind.as_str() {
        "runtime" => KeyKind::Runtime,
        "admin" => KeyKind::Admin,
        other => return Err(format!("Invalid kind '{}'. Must be 'runtime' or 'admin'.", other)),
    };
    store
        .set(&req.name, req.value.trim(), kind, req.force)
        .map_err(|e| e.to_string())?;
    Ok(format!("Stored {}", req.name))
}

#[tauri::command]
fn list_keys(include_admin: bool) -> Result<Vec<lkr_core::KeyEntry>, String> {
    let store = KeychainStore::new();
    store.list(include_admin).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_key, set_key, list_keys])
        .run(tauri::generate_context!())
        .expect("error while running LLM Key Ring");
}
