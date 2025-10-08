use crate::cli::UsernameArgs;
use crate::utils::{context::AppContext, http::HttpClient, output};
use anyhow::Result;
use console::style;
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct UsernameResult {
    pub platform: String,
    pub url: String,
    pub exists: bool,
    pub profile_data: Option<HashMap<String, String>>,
}
#[derive(Debug, Serialize, Deserialize, Default, Clone, ToSchema)]
pub struct UsernameRunSummary {
    pub results: Vec<UsernameResult>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub checked: usize,
    pub not_found: usize,
}

pub async fn run(args: UsernameArgs) -> Result<Vec<UsernameResult>> {
    let summary = run_with_summary(args).await?;
    Ok(summary.results)
}

pub async fn run_with_summary(args: UsernameArgs) -> Result<UsernameRunSummary> {
    let show_console = output::is_console() && !output::is_quiet();
    if show_console {
        println!(
            "{} Searching for username: {}",
            style("🔍").cyan(),
            style(&args.username).yellow().bold()
        );
    }
    let platforms = get_platforms(&args.platforms);
    let pb = if show_console {
        let bar = ProgressBar::new(platforms.len() as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        bar
    } else {
        ProgressBar::hidden()
    };
    let ctx = AppContext::current().execution();
    let client = HttpClient::from_shared(ctx.http.clone());
    let max_concurrent = {
        let settings = &ctx.config.settings;
        settings.max_threads.max(1)
    };
    let total_checked = platforms.len();

    let mut successes: Vec<UsernameResult> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut not_found_count: usize = 0;

    for chunk in platforms.chunks(max_concurrent) {
        let chunk_tasks: Vec<_> = chunk
            .iter()
            .map(|platform| {
                let username = args.username.clone();
                let client_clone = client.clone();
                let pb_clone = pb.clone();
                let platform_name = platform.name.clone();
                async move {
                    let result = check_platform(&client_clone, platform, &username).await;
                    pb_clone.inc(1);
                    if show_console {
                        pb_clone.set_message(format!("Checking {}", platform_name));
                    }
                    (platform_name, result)
                }
            })
            .collect();

        let chunk_results = join_all(chunk_tasks).await;

        for (platform_name, outcome) in chunk_results {
            match outcome {
                Ok(res) => {
                    if res.exists {
                        successes.push(res);
                    } else {
                        not_found_count += 1;
                        if show_console && args.format == "verbose" {
                            println!("  {} {}", style("✗").red(), platform_name);
                        }
                    }
                }
                Err(err) => {
                    errors.push(format!("{}: {}", platform_name, err));
                    if show_console && args.format == "verbose" {
                        eprintln!(
                            "  {} Error on {}: {}",
                            style("⚠").yellow(),
                            platform_name,
                            err
                        );
                    }
                }
            }
        }
    }

    pb.finish_and_clear();
    if show_console {
        println!("\n{}", style(style("Results:").green()).bold());
        println!("{}", style("════════").cyan());
    }

    let found_count = successes.len();
    if show_console {
        for res in &successes {
            println!(
                "  {} {} - {}",
                style(style("✓").green()).bold(),
                style(&res.platform).cyan(),
                style(&res.url).blue().underlined()
            );
            if let Some(data) = &res.profile_data {
                for (key, value) in data {
                    println!(
                        "      {} {}",
                        style(format!("{}:", style(key))).yellow(),
                        value
                    );
                }
            }
        }
    }

    if show_console {
        println!("\n{}", style("Summary:").bold());
        println!(
            "  Found: {} profiles",
            style(found_count.to_string()).green()
        );
        println!(
            "  Not found: {} platforms",
            style(not_found_count.to_string()).yellow()
        );
    }
    if let Some(output_file) = args.output.clone() {
        save_results(&output_file, &successes, &args.format)?;
        if show_console {
            println!(
                "\n{} Results saved to: {}",
                style("💾").cyan(),
                style(output_file).blue()
            );
        }
    }

    if show_console && !errors.is_empty() {
        println!("\n{}", style("Errors:").red());
        for error in &errors {
            println!("  {} {}", style("✗").red(), error);
        }
    }

    if successes.is_empty() {
        warnings.push("No platforms reported an existing profile".to_string());
    }

    let summary = UsernameRunSummary {
        results: successes,
        warnings,
        errors,
        checked: total_checked,
        not_found: not_found_count,
    };

    Ok(summary)
}
#[derive(Clone)]
struct Platform {
    name: String,
    url_template: String,
    #[allow(dead_code)]
    check_type: CheckType,
}
#[derive(Clone)]
#[allow(dead_code)]
enum CheckType {
    StatusCode,
    StringMatch(String),
    JsonField(String),
}
fn get_platforms(filter: &Option<String>) -> Vec<Platform> {
    let mut platforms = vec![
        Platform {
            name: "GitHub".to_string(),
            url_template: "https://github.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Twitter/X".to_string(),
            url_template: "https://x.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Instagram".to_string(),
            url_template: "https://www.instagram.com/{}/".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "LinkedIn".to_string(),
            url_template: "https://www.linkedin.com/in/{}/".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Reddit".to_string(),
            url_template: "https://www.reddit.com/user/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "TikTok".to_string(),
            url_template: "https://www.tiktok.com/@{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "YouTube".to_string(),
            url_template: "https://www.youtube.com/@{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Twitch".to_string(),
            url_template: "https://www.twitch.tv/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Steam".to_string(),
            url_template: "https://steamcommunity.com/id/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Pinterest".to_string(),
            url_template: "https://www.pinterest.com/{}/".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Telegram".to_string(),
            url_template: "https://t.me/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Medium".to_string(),
            url_template: "https://medium.com/@{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "DeviantArt".to_string(),
            url_template: "https://www.deviantart.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Spotify".to_string(),
            url_template: "https://open.spotify.com/user/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Snapchat".to_string(),
            url_template: "https://www.snapchat.com/add/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        // Additional platforms to reach 30+
        Platform {
            name: "Flickr".to_string(),
            url_template: "https://www.flickr.com/people/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Tumblr".to_string(),
            url_template: "https://{}.tumblr.com".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Vimeo".to_string(),
            url_template: "https://vimeo.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "SoundCloud".to_string(),
            url_template: "https://soundcloud.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Behance".to_string(),
            url_template: "https://www.behance.net/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Dribbble".to_string(),
            url_template: "https://dribbble.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "GitLab".to_string(),
            url_template: "https://gitlab.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Bitbucket".to_string(),
            url_template: "https://bitbucket.org/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Docker Hub".to_string(),
            url_template: "https://hub.docker.com/u/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "500px".to_string(),
            url_template: "https://500px.com/p/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Last.fm".to_string(),
            url_template: "https://www.last.fm/user/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Patreon".to_string(),
            url_template: "https://www.patreon.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "OnlyFans".to_string(),
            url_template: "https://onlyfans.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "Keybase".to_string(),
            url_template: "https://keybase.io/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
        Platform {
            name: "HackerOne".to_string(),
            url_template: "https://hackerone.com/{}".to_string(),
            check_type: CheckType::StatusCode,
        },
    ];
    // Filter platforms only if specified, otherwise use all
    if let Some(filter_str) = filter {
        if !filter_str.is_empty() {
            let filters: Vec<String> = filter_str
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .collect();
            platforms.retain(|p| filters.contains(&p.name.to_lowercase()));
        }
    }
    platforms
}
async fn check_platform(
    client: &HttpClient,
    platform: &Platform,
    username: &str,
) -> Result<UsernameResult> {
    let url = platform.url_template.replace("{}", username);

    // Enhanced existence check
    let exists = match client.get(&url).await {
        Ok(content) => {
            let content_lower = content.to_lowercase();
            // Check for common "not found" indicators
            !(content_lower.contains("user not found") ||
              content_lower.contains("page not found") ||
              content_lower.contains("404") ||
              content_lower.contains("nobody") ||
              content_lower.contains("doesn't exist") ||
              content_lower.contains("not available") ||
              content_lower.contains("profile not found") ||
              content_lower.contains("account not found") ||
              content_lower.contains("this account doesn't exist") ||
              content.is_empty() ||
              // Check for redirects to home page (title contains site name only)
              (content_lower.contains("<title>") && 
               (content_lower.contains("<title>github</title>") ||
                content_lower.contains("<title>twitter</title>") ||
                content_lower.contains("<title>instagram</title>"))))
        }
        Err(_) => {
            // If we can't fetch the content, try basic status code check
            client.check_url(&url).await.unwrap_or(false)
        }
    };

    Ok(UsernameResult {
        platform: platform.name.clone(),
        url: url.clone(),
        exists,
        profile_data: None,
    })
}
fn save_results(filename: &str, results: &[UsernameResult], format: &str) -> Result<()> {
    let successful_results: Vec<&UsernameResult> = results.iter().filter(|r| r.exists).collect();
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&successful_results)?;
            std::fs::write(filename, json)?;
        }
        "csv" => {
            let mut wtr = csv::Writer::from_path(filename)?;
            wtr.write_record(&["Platform", "URL", "Exists"])?;
            for result in successful_results {
                wtr.write_record(&[&result.platform, &result.url, "true"])?;
            }
            wtr.flush()?;
        }
        _ => {
            let mut content = String::new();
            for result in successful_results {
                content.push_str(&format!("{}: {}\n", result.platform, result.url));
            }
            std::fs::write(filename, content)?;
        }
    }
    Ok(())
}
