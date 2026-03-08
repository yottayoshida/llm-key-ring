use lkr_core::KeyStore;

pub(crate) fn cmd_usage(
    store: &impl KeyStore,
    provider: Option<&str>,
    refresh: bool,
    json: bool,
) -> lkr_core::Result<()> {
    let cache = lkr_core::UsageCache::default();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| lkr_core::Error::Usage(format!("Failed to start async runtime: {}", e)))?;

    let providers: Vec<String> = match provider {
        Some(p) => vec![p.to_lowercase()],
        None => {
            let avail = lkr_core::available_providers(store)?;
            if avail.is_empty() {
                eprintln!("No admin keys registered for usage tracking.\n");
                eprintln!("  Register an admin key first:");
                eprintln!("    lkr set openai:admin --kind admin");
                eprintln!("    lkr set anthropic:admin --kind admin");
                return Ok(());
            }
            avail
        }
    };

    let mut reports = Vec::new();
    let mut errors = Vec::new();
    for p in &providers {
        match rt.block_on(lkr_core::fetch_cost(store, p, &cache, refresh)) {
            Ok(report) => reports.push(report),
            Err(e) => {
                eprintln!("  {}: {}", p, e);
                errors.push(e);
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&reports).unwrap());
        // Return error if ALL fetches failed (partial success is OK)
        if reports.is_empty() && !errors.is_empty() {
            return Err(errors.remove(0));
        }
        return Ok(());
    }

    if reports.is_empty() {
        if errors.is_empty() {
            eprintln!("No usage data available.");
            return Ok(());
        }
        // All fetches failed — propagate the first error for exit code 1
        return Err(errors.remove(0));
    }

    for report in &reports {
        println!(
            "\n  {} — {} to {}",
            report.provider, report.period_start, report.period_end
        );
        println!("  {}", "-".repeat(50));

        for item in &report.line_items {
            println!(
                "    {:<30} {}",
                item.description,
                lkr_core::format_cost(item.cost_cents)
            );
        }

        println!(
            "  {:<32} {}",
            "Total",
            lkr_core::format_cost(report.total_cost_cents)
        );
    }

    if reports.len() > 1 {
        let grand_total: f64 = reports.iter().map(|r| r.total_cost_cents).sum();
        println!(
            "\n  {:<32} {}",
            "Grand Total",
            lkr_core::format_cost(grand_total)
        );
    }

    println!();
    Ok(())
}
