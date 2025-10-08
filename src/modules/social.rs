use crate::cli::SocialArgs;
use crate::utils::http::HttpClient;
use anyhow::Result;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Serialize, Deserialize)]
pub struct SocialResult {
    pub target: String,
    pub id_type: String,
    pub profiles: Vec<ProfileInfo>,
    pub analysis: Option<ProfileAnalysis>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub platform: String,
    pub url: String,
    pub found: bool,
    pub metadata: HashMap<String, String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileAnalysis {
    pub activity_level: String,
    pub common_interests: Vec<String>,
    pub likely_location: Option<String>,
    pub profile_age: Option<String>,
}
pub async fn run(args: SocialArgs) -> Result<()> {
    println!(
        "{} Social media reconnaissance for: {}",
        style("👤").cyan(),
        style(&args.target).yellow().bold()
    );
    println!("Identifier type: {}", style(&args.id_type).cyan());
    let platforms = get_social_platforms(&args.platforms);
    let pb = ProgressBar::new(platforms.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    let client = HttpClient::new()?;
    let mut profiles = vec![];
    for platform in platforms {
        pb.set_message(format!("Checking {}", platform));
        let profile =
            check_social_platform(&client, &platform, &args.target, &args.id_type).await?;
        profiles.push(profile);
        pb.inc(1);
    }
    pb.finish_and_clear();
    let analysis = if args.analyze {
        Some(analyze_profiles(&profiles))
    } else {
        None
    };
    let results = SocialResult {
        target: args.target.clone(),
        id_type: args.id_type.clone(),
        profiles,
        analysis,
    };
    display_results(&results);
    Ok(())
}
fn get_social_platforms(filter: &Option<String>) -> Vec<String> {
    let mut platforms = vec![
        "Facebook".to_string(),
        "Twitter/X".to_string(),
        "Instagram".to_string(),
        "LinkedIn".to_string(),
        "TikTok".to_string(),
        "YouTube".to_string(),
        "Reddit".to_string(),
        "Pinterest".to_string(),
        "Snapchat".to_string(),
        "Telegram".to_string(),
        "WhatsApp".to_string(),
        "GitHub".to_string(),
        "GitLab".to_string(),
        "Stack Overflow".to_string(),
        "Medium".to_string(),
        "Twitch".to_string(),
        "Steam".to_string(),
        "Spotify".to_string(),
        "SoundCloud".to_string(),
    ];
    if let Some(filter_str) = filter {
        let filters: Vec<String> = filter_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect();
        platforms.retain(|p| filters.iter().any(|f| p.to_lowercase().contains(f)));
    }
    platforms
}
async fn check_social_platform(
    client: &HttpClient,
    platform: &str,
    target: &str,
    id_type: &str,
) -> Result<ProfileInfo> {
    let url = build_profile_url(platform, target, id_type);
    let found = if !url.is_empty() {
        client.check_url(&url).await.unwrap_or(false)
    } else {
        false
    };
    let mut metadata = HashMap::new();
    if found {
        metadata.insert("status".to_string(), "active".to_string());
        metadata.insert(
            "last_checked".to_string(),
            chrono::Local::now().to_rfc3339(),
        );
    }
    Ok(ProfileInfo {
        platform: platform.to_string(),
        url,
        found,
        metadata,
    })
}
fn build_profile_url(platform: &str, target: &str, id_type: &str) -> String {
    match (platform, id_type) {
        ("Facebook", "username") => format!("https://www.facebook.com/{}", target),
        ("Twitter/X", "username") => format!("https://x.com/{}", target),
        ("Instagram", "username") => format!("https://www.instagram.com/{}/", target),
        ("LinkedIn", "username") => format!("https://www.linkedin.com/in/{}/", target),
        ("TikTok", "username") => format!("https://www.tiktok.com/@{}", target),
        ("YouTube", "username") => format!("https://www.youtube.com/@{}", target),
        ("Reddit", "username") => format!("https://www.reddit.com/user/{}", target),
        ("GitHub", "username") => format!("https://github.com/{}", target),
        ("GitLab", "username") => format!("https://gitlab.com/{}", target),
        ("Medium", "username") => format!("https://medium.com/@{}", target),
        ("Twitch", "username") => format!("https://www.twitch.tv/{}", target),
        ("Steam", "username") => format!("https://steamcommunity.com/id/{}", target),
        ("Pinterest", "username") => format!("https://www.pinterest.com/{}/", target),
        ("Telegram", "username") => format!("https://t.me/{}", target),
        _ => String::new(),
    }
}
fn analyze_profiles(profiles: &[ProfileInfo]) -> ProfileAnalysis {
    let active_count = profiles.iter().filter(|p| p.found).count();
    let total_count = profiles.len();
    let activity_level = match active_count * 100 / total_count.max(1) {
        0..=20 => "Low".to_string(),
        21..=50 => "Moderate".to_string(),
        51..=80 => "High".to_string(),
        _ => "Very High".to_string(),
    };
    let mut common_interests = vec![];
    let tech_platforms = ["GitHub", "GitLab", "Stack Overflow"];
    let tech_count = profiles
        .iter()
        .filter(|p| p.found && tech_platforms.contains(&p.platform.as_str()))
        .count();
    if tech_count > 0 {
        common_interests.push("Technology/Programming".to_string());
    }
    let gaming_platforms = ["Steam", "Twitch"];
    let gaming_count = profiles
        .iter()
        .filter(|p| p.found && gaming_platforms.contains(&p.platform.as_str()))
        .count();
    if gaming_count > 0 {
        common_interests.push("Gaming".to_string());
    }
    let content_platforms = ["YouTube", "TikTok", "Medium"];
    let content_count = profiles
        .iter()
        .filter(|p| p.found && content_platforms.contains(&p.platform.as_str()))
        .count();
    if content_count > 0 {
        common_interests.push("Content Creation".to_string());
    }
    ProfileAnalysis {
        activity_level,
        common_interests,
        likely_location: None,
        profile_age: None,
    }
}
fn display_results(results: &SocialResult) {
    println!("\n{}", style("Social Media Results:").green().bold());
    println!("{}", style("════════════════════").cyan());
    let found_profiles: Vec<&ProfileInfo> = results.profiles.iter().filter(|p| p.found).collect();
    let not_found_count = results.profiles.len() - found_profiles.len();
    if !found_profiles.is_empty() {
        println!("\n{} Found Profiles:", style("✓").green());
        for profile in found_profiles {
            println!(
                "  {} {}",
                style("•").cyan(),
                style(&profile.platform).bold()
            );
            println!(
                "    {} {}",
                style("URL:").yellow(),
                style(&profile.url).blue().underlined()
            );
            if !profile.metadata.is_empty() {
                for (key, value) in &profile.metadata {
                    println!("    {}: {}", style(key).yellow(), value);
                }
            }
        }
    }
    println!("\n{}", style("Summary:").bold());
    println!("  Total platforms checked: {}", results.profiles.len());
    println!(
        "  Profiles found: {}",
        style(results.profiles.len() - not_found_count).green()
    );
    println!("  Not found: {}", style(not_found_count).yellow());
    if let Some(analysis) = &results.analysis {
        println!("\n{}", style("Profile Analysis:").magenta().bold());
        println!("{}", style("═════════════════").cyan());
        println!(
            "  Activity Level: {}",
            style(&analysis.activity_level).cyan()
        );
        if !analysis.common_interests.is_empty() {
            println!("  Common Interests:");
            for interest in &analysis.common_interests {
                println!("    • {}", style(interest).yellow());
            }
        }
        if let Some(location) = &analysis.likely_location {
            println!("  Likely Location: {}", style(location).cyan());
        }
        if let Some(age) = &analysis.profile_age {
            println!("  Profile Age: {}", style(age).cyan());
        }
    }
}
