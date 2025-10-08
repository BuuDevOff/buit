use crate::cli::ReverseImageArgs;
use anyhow::Result;
use console::style;
use reqwest::Client;
use std::fs;
use std::path::Path;
use url::Url;

pub async fn run(args: ReverseImageArgs) -> Result<()> {
    println!(
        "{} Reverse image search: {}",
        style("🔍").cyan(),
        style(&args.image).yellow().bold()
    );

    let engines = parse_engines(&args.engines.unwrap_or_else(|| "google,bing".to_string()));

    println!("🔎 Search engines: {}", engines.join(", "));

    // Check if input is URL or file path
    let image_data = if is_url(&args.image) {
        download_image(&args.image).await?
    } else if Path::new(&args.image).exists() {
        load_local_image(&args.image)?
    } else {
        return Err(anyhow::anyhow!("Image not found: {}", args.image));
    };

    println!(
        "📷 Image loaded: {} bytes",
        style(image_data.len().to_string()).yellow()
    );

    let mut warnings = Vec::new();
    for engine in engines {
        warnings.push(format!(
            "Reverse image search via {} is not implemented; upload the image manually",
            engine
        ));
    }

    if !warnings.is_empty() {
        println!("\n{}", style("Warnings:").yellow());
        for warning in warnings {
            println!("  {} {}", style("⚠").yellow(), warning);
        }
    }

    Ok(())
}

fn parse_engines(engines_str: &str) -> Vec<String> {
    engines_str
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect()
}

fn is_url(input: &str) -> bool {
    Url::parse(input).is_ok()
}

async fn download_image(url: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download image: HTTP {}",
            response.status()
        ));
    }

    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}

fn load_local_image(path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;

    // Validate it's an image file
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    match extension.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" => Ok(bytes),
        _ => Err(anyhow::anyhow!("Unsupported image format: {}", extension)),
    }
}
