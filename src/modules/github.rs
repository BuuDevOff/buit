use crate::cli::GithubArgs;
use crate::config::Config;
use crate::utils::http::{HttpClient, HttpError};
use anyhow::Result;
use console::style;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubResult {
    pub target: String,
    pub user_info: Option<UserInfo>,
    pub repositories: Vec<Repository>,
    pub secrets_found: Vec<Secret>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub login: String,
    pub name: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub email: Option<String>,
    pub company: Option<String>,
    pub public_repos: u32,
    pub followers: u32,
    pub following: u32,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Repository {
    pub name: String,
    pub description: Option<String>,
    pub language: Option<String>,
    pub stars: u32,
    pub forks: u32,
    pub updated_at: String,
    pub url: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Secret {
    pub repo: String,
    pub file: String,
    pub pattern: String,
    pub line: u32,
}
pub async fn run(args: GithubArgs) -> Result<()> {
    println!(
        "{} GitHub OSINT: {}",
        style("🔍").cyan(),
        style(&args.target).yellow().bold()
    );
    let client = HttpClient::new()?;
    let config = Config::load()?;
    let username = extract_username(&args.target);
    println!("Analyzing user: {}", style(&username).cyan());
    let mut result = GitHubResult {
        target: args.target.clone(),
        user_info: None,
        repositories: vec![],
        secrets_found: vec![],
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    if config.get_api_key("github_token").is_none() {
        result
            .warnings
            .push("API key github_token missing; rate limits may apply".to_string());
    }

    let (user_info, mut warnings, mut errors) = get_user_info(&client, &username).await?;
    result.user_info = user_info;
    result.warnings.append(&mut warnings);
    result.errors.append(&mut errors);
    if args.repos {
        println!("\n{} Fetching repositories...", style("📁").cyan());
        let (repos, mut warnings, mut errors) = get_repositories(&client, &username).await?;
        result.repositories = repos;
        result.warnings.append(&mut warnings);
        result.errors.append(&mut errors);
    }
    if args.secrets {
        println!("\n{} Scanning for secrets...", style("🔒").cyan());
        let (secrets, mut warnings, mut errors) = scan_for_secrets(&client, &username).await?;
        result.secrets_found = secrets;
        result.warnings.append(&mut warnings);
        result.errors.append(&mut errors);
    }
    display_results(&result);
    Ok(())
}
fn extract_username(target: &str) -> String {
    if target.starts_with("https://github.com/") {
        target
            .replace("https://github.com/", "")
            .split('/')
            .next()
            .unwrap_or(target)
            .to_string()
    } else if target.starts_with("github.com/") {
        target
            .replace("github.com/", "")
            .split('/')
            .next()
            .unwrap_or(target)
            .to_string()
    } else {
        target.to_string()
    }
}
async fn get_user_info(
    client: &HttpClient,
    username: &str,
) -> Result<(Option<UserInfo>, Vec<String>, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    let api_url = format!("https://api.github.com/users/{}", username);

    match client.get(&api_url).await {
        Ok(response) => {
            if let Ok(github_user) = serde_json::from_str::<serde_json::Value>(&response) {
                if github_user.get("message").is_some() {
                    warnings.push(format!("GitHub user {} not found", username));
                    return Ok((None, warnings, errors));
                }

                let user = UserInfo {
                    login: github_user
                        .get("login")
                        .and_then(|v| v.as_str())
                        .unwrap_or(username)
                        .to_string(),
                    name: github_user
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    bio: github_user
                        .get("bio")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    location: github_user
                        .get("location")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    email: github_user
                        .get("email")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    company: github_user
                        .get("company")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    public_repos: github_user
                        .get("public_repos")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    followers: github_user
                        .get("followers")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    following: github_user
                        .get("following")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                };

                return Ok((Some(user), warnings, errors));
            }
            errors.push("Failed to parse GitHub user payload".to_string());
        }
        Err(HttpError::BadStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
            warnings.push(format!("GitHub user {} not found", username));
        }
        Err(err) => {
            errors.push(format!("GitHub user request failed: {}", err));
        }
    }

    Ok((None, warnings, errors))
}

async fn get_repositories(
    client: &HttpClient,
    username: &str,
) -> Result<(Vec<Repository>, Vec<String>, Vec<String>)> {
    let mut repos = Vec::new();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    let api_url = format!(
        "https://api.github.com/users/{}/repos?sort=updated&per_page=10",
        username
    );

    match client.get(&api_url).await {
        Ok(response) => {
            if let Ok(github_repos) = serde_json::from_str::<serde_json::Value>(&response) {
                if let Some(repo_array) = github_repos.as_array() {
                    for repo_data in repo_array.iter().take(10) {
                        repos.push(Repository {
                            name: repo_data
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            description: repo_data
                                .get("description")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            language: repo_data
                                .get("language")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            stars: repo_data
                                .get("stargazers_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32,
                            forks: repo_data
                                .get("forks_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32,
                            updated_at: repo_data
                                .get("updated_at")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            url: repo_data
                                .get("html_url")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        });
                    }
                    return Ok((repos, warnings, errors));
                }
                warnings.push("GitHub repositories payload empty".to_string());
            } else {
                errors.push("Failed to parse GitHub repositories payload".to_string());
            }
        }
        Err(HttpError::BadStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
            warnings.push(format!("No repositories found for {}", username));
        }
        Err(err) => {
            errors.push(format!("GitHub repositories request failed: {}", err));
        }
    }

    Ok((repos, warnings, errors))
}

async fn scan_for_secrets(
    _client: &HttpClient,
    username: &str,
) -> Result<(Vec<Secret>, Vec<String>, Vec<String>)> {
    let warnings = vec![format!(
        "Secret scanning for {} not implemented; use dedicated tooling",
        username
    )];
    Ok((Vec::new(), warnings, Vec::new()))
}
fn display_results(result: &GitHubResult) {
    println!("\n{}", style("GitHub OSINT Results:").green().bold());
    println!("{}", style("════════════════════").cyan());
    if let Some(user) = &result.user_info {
        println!(
            "  {} {}",
            style("Username:").yellow(),
            style(&user.login).cyan()
        );
        if let Some(name) = &user.name {
            println!("  {} {}", style("Name:").yellow(), style(name).cyan());
        }
        if let Some(bio) = &user.bio {
            println!("  {} {}", style("Bio:").yellow(), bio);
        }
        if let Some(location) = &user.location {
            println!(
                "  {} {}",
                style("Location:").yellow(),
                style(location).cyan()
            );
        }
        if let Some(email) = &user.email {
            println!("  {} {}", style("Email:").yellow(), style(email).cyan());
        }
        if let Some(company) = &user.company {
            println!("  {} {}", style("Company:").yellow(), style(company).cyan());
        }
        println!(
            "  {} {} public, {} followers, {} following",
            style("Stats:").yellow(),
            style(user.public_repos.to_string()).green(),
            style(user.followers.to_string()).green(),
            style(user.following.to_string()).green()
        );
    }
    if !result.repositories.is_empty() {
        println!("\n{}", style("Repositories:").yellow());
        for repo in &result.repositories {
            println!(
                "  • {} (⭐ {}, 🍴 {})",
                style(&repo.name).cyan().bold(),
                repo.stars,
                repo.forks
            );
            if let Some(desc) = &repo.description {
                println!("    {}", style(desc).dim());
            }
            if let Some(lang) = &repo.language {
                println!("    Language: {}", style(lang).green());
            }
            println!("    {}", style(&repo.url).blue().underlined());
        }
    }
    if !result.secrets_found.is_empty() {
        println!("\n{}", style("⚠ Potential Secrets Found:").red().bold());
        for secret in &result.secrets_found {
            println!(
                "  {} {}:{}",
                style("⚠").red(),
                style(&secret.repo).yellow(),
                secret.line
            );
            println!("    File: {}", style(&secret.file).cyan());
            println!("    Pattern: {}", style(&secret.pattern).red());
        }
    }
    if !result.warnings.is_empty() {
        println!("\n{}", style("Warnings:").yellow());
        for warning in &result.warnings {
            println!("  {} {}", style("⚠").yellow(), warning);
        }
    }
    if !result.errors.is_empty() {
        println!("\n{}", style("Errors:").red());
        for error in &result.errors {
            println!("  {} {}", style("✗").red(), error);
        }
    }
}
