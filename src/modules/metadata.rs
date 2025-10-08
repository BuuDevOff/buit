use crate::cli::MetadataArgs;
use anyhow::Result;
use console::style;
use std::fs;
use std::path::Path;
// use kamadak_exif::{Reader, In, Tag};
use lopdf::Document;
use serde_json::json;

pub fn run(args: MetadataArgs) -> Result<()> {
    println!(
        "{} Extracting metadata from: {}",
        style("📄").cyan(),
        style(&args.file).yellow().bold()
    );

    let path = Path::new(&args.file);

    if !path.exists() {
        println!("{} File not found: {}", style("❌").red(), args.file);
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("unknown")
        .to_lowercase();

    println!("\n{} Basic File Information", style("📋").cyan());
    println!("{}", "=".repeat(40));
    println!(
        "📁 File: {}",
        style(path.file_name().unwrap().to_string_lossy()).yellow()
    );
    println!(
        "📏 Size: {} bytes ({:.2} KB)",
        file_size,
        file_size as f64 / 1024.0
    );
    println!("🏷️  Type: {}", style(&extension).cyan());

    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            let datetime =
                chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0).unwrap_or_default();
            println!("📅 Modified: {}", datetime.format("%Y-%m-%d %H:%M:%S UTC"));
        }
    }

    match extension.as_str() {
        "jpg" | "jpeg" | "tiff" | "tif" => {
            println!("\n{} JPEG/TIFF image detected", style("📸").yellow());
            println!(
                "{} EXIF extraction requires kamadak-exif crate",
                style("⚠️").yellow()
            );
        }
        "pdf" => {
            extract_pdf_metadata(path)?;
        }
        "png" | "gif" | "bmp" => {
            println!(
                "\n{} Image file detected but no EXIF support for {}",
                style("📸").yellow(),
                extension.to_uppercase()
            );
        }
        "mp4" | "avi" | "mov" | "mkv" => {
            println!("\n{} Video file detected", style("🎥").yellow());
            // Video metadata extraction could be added here
        }
        "mp3" | "wav" | "flac" | "ogg" => {
            println!("\n{} Audio file detected", style("🎵").yellow());
            // Audio metadata extraction could be added here
        }
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" => {
            println!("\n{} Office document detected", style("📄").yellow());
            // Office document metadata could be added here
        }
        _ => {
            println!(
                "\n{} No specific metadata extractor for file type: {}",
                style("⚠️").yellow(),
                extension.to_uppercase()
            );
        }
    }

    if let Some(format) = &args.format {
        if format == "json" {
            output_json_format(path, file_size, &extension)?;
        }
    }

    Ok(())
}

// EXIF extraction function - disabled until kamadak-exif is added
/*
fn extract_image_metadata(path: &Path) -> Result<()> {
    println!("\n{} EXIF Data", "📸style(").cyan());
    println!("{}", "=".repeat(40));
    println!("{} EXIF extraction requires additional dependencies", style("⚠️").yellow());
    Ok(())
}
*/

fn extract_pdf_metadata(path: &Path) -> Result<()> {
    println!("\n{} PDF Metadata", style("📄").cyan());
    println!("{}", "=".repeat(40));

    match Document::load(path) {
        Ok(doc) => {
            let page_count = doc.get_pages().len();
            println!("📊 PDF Statistics:");
            println!("   Pages: {}", style(page_count.to_string()).yellow());

            // Extract basic PDF info
            if let Ok(info) = doc.trailer.get(b"Info") {
                if let Ok(info_dict) = info.as_dict() {
                    for (key, value) in info_dict.iter() {
                        if let Ok(key_str) = std::str::from_utf8(key) {
                            match key_str {
                                "Title" => {
                                    if let Ok(title_bytes) = value.as_str() {
                                        if let Ok(title_str) = std::str::from_utf8(title_bytes) {
                                            println!("   Title: {}", style(title_str).cyan());
                                        }
                                    }
                                }
                                "Author" => {
                                    if let Ok(author_bytes) = value.as_str() {
                                        if let Ok(author_str) = std::str::from_utf8(author_bytes) {
                                            println!("   Author: {}", style(author_str).cyan());
                                        }
                                    }
                                }
                                "Subject" => {
                                    if let Ok(subject_bytes) = value.as_str() {
                                        if let Ok(subject_str) = std::str::from_utf8(subject_bytes)
                                        {
                                            println!("   Subject: {}", style(subject_str).cyan());
                                        }
                                    }
                                }
                                "Creator" => {
                                    if let Ok(creator_bytes) = value.as_str() {
                                        if let Ok(creator_str) = std::str::from_utf8(creator_bytes)
                                        {
                                            println!("   Creator: {}", style(creator_str).cyan());
                                        }
                                    }
                                }
                                "Producer" => {
                                    if let Ok(producer_bytes) = value.as_str() {
                                        if let Ok(producer_str) =
                                            std::str::from_utf8(producer_bytes)
                                        {
                                            println!("   Producer: {}", style(producer_str).cyan());
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("{} Could not read PDF: {}", style("⚠️").yellow(), e);
        }
    }

    Ok(())
}

fn output_json_format(path: &Path, file_size: u64, extension: &str) -> Result<()> {
    let metadata = fs::metadata(path)?;

    let mut json_output = json!({
        "file_info": {
            "name": path.file_name().unwrap().to_string_lossy(),
            "size_bytes": file_size,
            "size_kb": file_size as f64 / 1024.0,
            "extension": extension,
            "type": get_file_type(extension)
        }
    });

    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            json_output["file_info"]["modified_timestamp"] = json!(duration.as_secs());
        }
    }

    println!("\n{} JSON Output:", style("💾").cyan());
    println!("{}", serde_json::to_string_pretty(&json_output)?);

    Ok(())
}

fn get_file_type(extension: &str) -> &'static str {
    match extension {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" => "image",
        "mp4" | "avi" | "mov" | "mkv" | "wmv" | "flv" => "video",
        "mp3" | "wav" | "flac" | "ogg" | "aac" => "audio",
        "pdf" => "document",
        "doc" | "docx" | "txt" | "rtf" => "document",
        "xls" | "xlsx" | "csv" => "spreadsheet",
        "ppt" | "pptx" => "presentation",
        "zip" | "rar" | "7z" | "tar" | "gz" => "archive",
        _ => "unknown",
    }
}
