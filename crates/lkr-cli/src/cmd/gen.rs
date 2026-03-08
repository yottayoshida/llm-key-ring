use crate::util::confirm;
use lkr_core::KeyStore;
use std::path::Path;

pub(crate) fn cmd_gen(
    store: &impl KeyStore,
    template: &str,
    output: Option<&str>,
    force: bool,
    stdout_is_tty: bool,
) -> lkr_core::Result<()> {
    // v0.2.0 TTY guard: block gen in non-interactive environments unless --force.
    // Generated files contain resolved secrets — risky in agent/CI contexts.
    if !stdout_is_tty && !force {
        return Err(lkr_core::Error::TtyGuard {
            message: "`lkr gen` is blocked in non-interactive environments.\n  \
                Use `lkr exec -- <command>` to inject keys as env vars instead.\n  \
                Or use `lkr gen --force` to override."
                .to_string(),
        });
    }

    let template_path = Path::new(template);
    if !template_path.exists() {
        return Err(lkr_core::Error::Template(format!(
            "Template file not found: {}",
            template
        )));
    }

    // Derive output path: .env.example → .env, foo.template → foo
    let output_path = match output {
        Some(o) => std::path::PathBuf::from(o),
        None => {
            let name = template_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let derived = if name.ends_with(".example") {
                name.trim_end_matches(".example").to_string()
            } else if name.ends_with(".template") {
                name.trim_end_matches(".template").to_string()
            } else {
                return Err(lkr_core::Error::Template(
                    "Cannot derive output path. Use -o to specify output file.".to_string(),
                ));
            };
            template_path
                .parent()
                .unwrap_or(Path::new("."))
                .join(derived)
        }
    };

    // Check if output exists and not --force
    if output_path.exists()
        && !force
        && !confirm(&format!(
            "Output file '{}' already exists. Overwrite? [y/N] ",
            output_path.display()
        ))
    {
        eprintln!("Cancelled.");
        return Ok(());
    }

    // .gitignore check (skipped outside git repos)
    if let Some(false) = lkr_core::check_gitignore(&output_path) {
        eprintln!(
            "Warning: '{}' is NOT in .gitignore. Generated files may contain secrets!",
            output_path.display()
        );
        eprintln!("  Consider adding it to .gitignore before committing.");
    }

    // Generate
    let result = lkr_core::generate(store, template_path, &output_path)?;

    // Report
    let resolved: Vec<_> = result
        .resolutions
        .iter()
        .filter(|r| r.key_name.is_some())
        .collect();
    let unresolved: Vec<_> = result
        .resolutions
        .iter()
        .filter(|r| r.key_name.is_none())
        .collect();

    if !resolved.is_empty() {
        eprintln!("  Resolved from Keychain:");
        for r in &resolved {
            eprintln!(
                "    {:<24} <- {}",
                r.placeholder,
                r.key_name.as_deref().unwrap_or("?")
            );
            if r.alternatives.len() > 1 {
                let others: Vec<&str> = r
                    .alternatives
                    .iter()
                    .filter(|a| Some(a.as_str()) != r.key_name.as_deref())
                    .map(|a| a.as_str())
                    .collect();
                if !others.is_empty() {
                    eprintln!("      (also available: {})", others.join(", "));
                }
            }
        }
    }

    if !unresolved.is_empty() {
        eprintln!("  Kept as-is (no matching key):");
        for r in &unresolved {
            eprintln!("    {}", r.placeholder);
        }
    }

    eprintln!(
        "\n  Generated: {} ({} resolved, {} unresolved)",
        output_path.display(),
        resolved.len(),
        unresolved.len()
    );

    Ok(())
}
