use crate::util::confirm;
use lkr_core::KeyStore;

pub(crate) fn cmd_rm(store: &impl KeyStore, name: &str, force: bool) -> lkr_core::Result<()> {
    if !force && !confirm(&format!("Remove key '{}'? [y/N] ", name)) {
        eprintln!("Cancelled.");
        return Ok(());
    }

    store.delete(name)?;
    eprintln!("Removed {}", name);
    Ok(())
}
