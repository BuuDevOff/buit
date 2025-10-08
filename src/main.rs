mod cli;
mod config;
mod modules;
mod setup;
mod types;
mod utils;
use anyhow::Result;
use clap::Parser;
use console::style;
use figlet_rs::FIGfont;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

use crate::types::ApiEnvelope;
use utils::context::{AppContext, OutputMode};
use utils::http::HttpCtx;
use utils::output;

#[cfg(debug_assertions)]
use tracing_appender;
#[cfg(debug_assertions)]
use tracing_subscriber::{
    self, filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt,
};

// Use mimalloc as global allocator to fix Windows memory fragmentation
#[cfg(windows)]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Custom panic hook to handle memory allocation errors gracefully
fn setup_panic_handler() {
    std::panic::set_hook(Box::new(|panic_info| {
        if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            if s.contains("memory allocation") {
                eprintln!("\n⚠️  Memory allocation error detected.");
                eprintln!("💡 Try using fewer platforms: buit username test -p \"github,twitter\"");
                eprintln!("🔧 Or try sequential mode: buit username test --sequential");
                // Force garbage collection before exit on Windows
                #[cfg(windows)]
                {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    let _ = panic_info;
                }
                std::process::exit(1);
            }
        }
        eprintln!("Program panicked: {:?}", panic_info);
    }));
}
fn init_terminal() {
    #[cfg(windows)]
    {
        let _ = console::Term::stdout().features().colors_supported();
    }
}

fn print_info_box() {
    if !output::is_console() || output::is_quiet() {
        return;
    }
    let content = format!(
        "{}\n{}\n{}\n{}\n{}\n\n{} {} {}\n{} {} {}\n{} {} {}\n{} {} {}",
        style("╔═══════════════════════════════════════════════╗")
            .cyan()
            .bold(),
        style("║      Buu Undercover Intelligence Toolkit      ║")
            .cyan()
            .bold(),
        style("║       Advanced OSINT Security Framework       ║")
            .green()
            .bold(),
        style("║      For Authorized Security Testing Only     ║").yellow(),
        style("╚═══════════════════════════════════════════════╝")
            .cyan()
            .bold(),
        style("📧").red(),
        style("Copyright ©").white(),
        style("BuuDevOff - Open-Source Project").cyan().bold(),
        style("🌟").yellow(),
        style("Like this tool? Star the repo:").white(),
        style("https://github.com/BuuDevOff/BUIT")
            .blue()
            .underlined(),
        style("🚀").green(),
        style("Share with the community &").white(),
        style("contribute!").green().bold(),
        style("💡").yellow(),
        style("Help & Usage:").white(),
        style("buit --help (built-in documentation)").cyan()
    );
    println!("{}", content);
}
#[tokio::main]
async fn main() -> Result<()> {
    setup_panic_handler();
    init_terminal();

    #[cfg(debug_assertions)]
    {
        // Setup structured logging with both console and file output (debug only)
        let file_appender = tracing_appender::rolling::daily("logs", "buit.log");
        let (non_blocking_file, _guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(LevelFilter::DEBUG)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(false),
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking_file)
                    .with_ansi(false)
                    .with_level(true)
                    .with_target(true),
            )
            .init();

        // Prevent _guard from being dropped immediately
        std::mem::forget(_guard);
    }

    let cli = cli::Cli::parse();

    let output_mode = if cli.json {
        OutputMode::Json
    } else if cli.ndjson {
        OutputMode::NdJson
    } else {
        OutputMode::Console
    };

    let tty = console::Term::stdout().is_term();
    let colors_enabled = tty && matches!(output_mode, OutputMode::Console);
    console::set_colors_enabled(colors_enabled);

    let config = Arc::new(config::Config::load()?);

    let cache_ttl = config.settings.http_cache_ttl_seconds.unwrap_or(120);

    let shared_cache = if cache_ttl == 0 {
        None
    } else {
        Some(Arc::new(
            Cache::builder()
                .max_capacity(2_048)
                .time_to_live(Duration::from_secs(cache_ttl.min(3600)))
                .build(),
        ))
    };

    let http_ctx = Arc::new(HttpCtx::new(&config, shared_cache.clone())?);

    AppContext::initialize(AppContext {
        output_mode,
        quiet: cli.quiet || !matches!(output_mode, OutputMode::Console),
        colors_enabled,
        http: Arc::clone(&http_ctx),
        config: Arc::clone(&config),
    });

    if output::is_console() && !output::is_quiet() {
        match FIGfont::standard() {
            Ok(standard_font) => {
                if let Some(text) = standard_font.convert("BUIT") {
                    println!("{}", style(text.to_string()).magenta().bold());
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not load ASCII art font: {}", e);
                println!("{}", style("BUIT").magenta().bold());
            }
        }
        print_info_box();
        println!();
    }
    if let Err(e) = setup::check_and_setup() {
        output::eprintln(format!("Setup error: {}", e));
    }

    if cli.api {
        return modules::api::start_api_server(modules::api::ApiServerOptions {
            host: cli.host.clone(),
            port: cli.port,
            cors_permissive: cli.cors_permissive,
            token: cli.api_token.clone(),
        })
        .await;
    }

    // Check for updates at startup if not in API mode
    if let Err(_e) = modules::autoupdater::check_for_updates_at_startup().await {
        #[cfg(debug_assertions)]
        eprintln!("Update check error: {}", _e);
    }

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            eprintln!(
                "{} No command specified. Use --help for usage information.",
                style("❌").red()
            );
            return Ok(());
        }
    };

    match command {
        cli::Commands::Username(args) => {
            if output::is_structured() {
                let summary = modules::username::run_with_summary(args).await?;
                let warnings = summary.warnings.clone();
                let errors = summary.errors.clone();
                let envelope = ApiEnvelope::new(Some(summary), warnings, errors);
                output::emit_json(&envelope)?;
            } else {
                modules::username::run(args).await?;
            }
        }
        cli::Commands::Email(args) => {
            guard_structured_output()?;
            modules::email::run(args).await?;
        }
        cli::Commands::Search(args) => {
            guard_structured_output()?;
            modules::search::run(args).await?;
        }
        cli::Commands::Dork(args) => {
            guard_structured_output()?;
            modules::dork::run(args).await?;
        }
        cli::Commands::Social(args) => {
            guard_structured_output()?;
            modules::social::run(args).await?;
        }
        cli::Commands::Config(args) => {
            guard_structured_output()?;
            config::manage::run(args)?;
        }
        cli::Commands::Phone(args) => {
            guard_structured_output()?;
            modules::phone::run(args).await?;
        }
        cli::Commands::Ip(args) => {
            let result = modules::ip::run(args).await?;
            if output::is_structured() {
                let warnings = result.warnings.clone();
                let errors = result.errors.clone();
                let envelope = ApiEnvelope::new(Some(result), warnings, errors);
                output::emit_json(&envelope)?;
            }
        }
        cli::Commands::Domain(args) => {
            guard_structured_output()?;
            modules::domain::run(args).await?;
        }
        cli::Commands::Leaks(args) => {
            guard_structured_output()?;
            modules::leaks::run(args).await?;
        }
        cli::Commands::Metadata(args) => {
            guard_structured_output()?;
            modules::metadata::run(args)?;
        }
        cli::Commands::Subdomain(args) => {
            guard_structured_output()?;
            modules::subdomain::run(args).await?;
        }
        cli::Commands::Shodan(args) => {
            guard_structured_output()?;
            modules::shodan::run(args).await?;
        }
        cli::Commands::Portscan(args) => {
            guard_structured_output()?;
            modules::portscan::run(args).await?;
        }
        cli::Commands::Whois(args) => {
            guard_structured_output()?;
            modules::whois::run(args).await?;
        }
        cli::Commands::ReverseImage(args) => {
            guard_structured_output()?;
            modules::reverse_image::run(args).await?;
        }
        cli::Commands::Github(args) => {
            guard_structured_output()?;
            modules::github::run(args).await?;
        }
        cli::Commands::Hash(args) => {
            guard_structured_output()?;
            modules::hash::run(args).await?;
        }
        cli::Commands::Urlscan(args) => {
            guard_structured_output()?;
            modules::urlscan::run(args).await?;
        }
        cli::Commands::Wayback(args) => {
            guard_structured_output()?;
            modules::wayback::run(args).await?;
        }
        cli::Commands::Geoip(args) => {
            guard_structured_output()?;
            modules::geoip::run(args).await?;
        }
        cli::Commands::Report(args) => {
            guard_structured_output()?;
            modules::report::run(args)?;
        }
        cli::Commands::Interactive => {
            guard_structured_output()?;
            modules::interactive::run().await?;
        }
        cli::Commands::Setup => {
            guard_structured_output()?;
            setup::force_setup().await?;
        }

        // New high-priority modules
        cli::Commands::ReverseDns(args) => {
            guard_structured_output()?;
            modules::reverse_dns::run(args).await?;
        }
        cli::Commands::AsnLookup(args) => {
            guard_structured_output()?;
            modules::asn_lookup::run(args).await?;
        }
        cli::Commands::SslCert(args) => {
            guard_structured_output()?;
            modules::ssl_cert_simple::run(args).await?;
        }
        cli::Commands::BreachCheck(args) => {
            guard_structured_output()?;
            modules::breach_check::run(args).await?;
        }
        cli::Commands::Update(args) => {
            guard_structured_output()?;
            modules::autoupdater::run(args).await?;
        }
        #[cfg(debug_assertions)]
        cli::Commands::Check(args) => {
            run_debug_check(args).await?;
        }
    }
    Ok(())
}

fn guard_structured_output() -> Result<()> {
    if output::is_structured() {
        output::eprintln(
            "Structured output is not yet available for this command. Use console mode instead.",
        );
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn assign_check_slot(
    value: String,
    username: &mut Option<String>,
    ip: &mut Option<String>,
    domain: &mut Option<String>,
) {
    if username.is_none() {
        *username = Some(value);
    } else if ip.is_none() {
        *ip = Some(value);
    } else if domain.is_none() {
        *domain = Some(value);
    }
}

#[cfg(debug_assertions)]
fn parse_check_tokens(tokens: Vec<String>) -> (Option<String>, Option<String>, Option<String>) {
    let mut username = None;
    let mut ip = None;
    let mut domain = None;
    let mut pending: Option<String> = None;

    for token in tokens {
        if token.starts_with("//") {
            if let Some(value) = pending.take() {
                let key = token.trim_start_matches('/').to_ascii_lowercase();
                match key.as_str() {
                    "username" | "user" | "handle" => username = Some(value),
                    "ip" | "addr" => ip = Some(value),
                    "domain" | "domaine" | "host" | "cert" => domain = Some(value),
                    _ => assign_check_slot(value, &mut username, &mut ip, &mut domain),
                }
            }
        } else {
            if let Some(previous) = pending.replace(token) {
                assign_check_slot(previous, &mut username, &mut ip, &mut domain);
            }
        }
    }

    if let Some(value) = pending.take() {
        assign_check_slot(value, &mut username, &mut ip, &mut domain);
    }

    (username, ip, domain)
}

#[cfg(debug_assertions)]
async fn run_debug_check(args: cli::CheckArgs) -> Result<()> {
    use crate::cli::{DomainArgs, IpArgs, UsernameArgs};

    let (username, ip, domain) = parse_check_tokens(args.tokens);

    if username.is_none() && ip.is_none() && domain.is_none() {
        println!(
            "{} Provide at least one target using markers like '//username', '//ip' or '//domaine'.",
            style("⚠").yellow()
        );
        return Ok(());
    }

    if let Some(user) = username {
        println!(
            "{} Checking username module with target {}",
            style("🧪").cyan(),
            style(&user).yellow().bold()
        );
        let summary = modules::username::run_with_summary(UsernameArgs {
            username: user.clone(),
            format: "text".to_string(),
            output: None,
            platforms: None,
        })
        .await?;
        println!(
            "{} Platforms checked: {}, profiles found: {} (errors: {})",
            style("→").cyan(),
            summary.checked,
            summary.results.len(),
            summary.errors.len()
        );
    }

    if let Some(addr) = ip {
        println!(
            "{} Checking IP module with target {}",
            style("🧪").cyan(),
            style(&addr).yellow().bold()
        );
        let result = modules::ip::run(IpArgs {
            ip: addr.clone(),
            no_reverse: false,
            no_asn: false,
            no_geo: false,
        })
        .await?;
        println!(
            "{} ASN: {} | Geo: {} | warnings: {} | errors: {}",
            style("→").cyan(),
            result.asn.as_ref().map(|_| "yes").unwrap_or("no"),
            result.geolocation.as_ref().map(|_| "yes").unwrap_or("no"),
            result.warnings.len(),
            result.errors.len()
        );
    }

    if let Some(dom) = domain {
        println!(
            "{} Checking domain module with target {}",
            style("🧪").cyan(),
            style(&dom).yellow().bold()
        );
        modules::domain::run(DomainArgs {
            domain: dom.clone(),
            dns: true,
            ssl: true,
            whois: true,
        })
        .await?;
    }

    println!("{} Debug check complete", style("✅").green());
    Ok(())
}
