// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use lkr_core::{KeyKind, KeyStore, KeychainStore, mask_value};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

/// IPC Security: returns ONLY masked_value — raw key NEVER crosses the IPC boundary.
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

/// IPC Security: `req.value` is zeroized after storage to prevent the raw key
/// from lingering in process memory. See docs/SECURITY.md for the full threat model.
#[tauri::command]
fn set_key(mut req: SetKeyRequest) -> Result<String, String> {
    let store = KeychainStore::new();
    let kind = match req.kind.as_str() {
        "runtime" => KeyKind::Runtime,
        "admin" => KeyKind::Admin,
        other => {
            req.value.zeroize();
            return Err(format!("Invalid kind '{}'. Must be 'runtime' or 'admin'.", other));
        }
    };
    let name = req.name.clone();
    let result = store
        .set(&req.name, req.value.trim(), kind, req.force)
        .map_err(|e| e.to_string());

    // Zeroize raw key value before returning (regardless of success/error)
    req.value.zeroize();

    result.map(|()| format!("Stored {}", name))
}

/// IPC Security: KeyEntry contains only masked_value — no raw values exposed.
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
