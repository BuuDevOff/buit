use crate::cli::SearchArgs;
use crate::utils::http::HttpClient;
use anyhow::Result;
use console::style;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub engine: String,
}
pub async fn run(args: SearchArgs) -> Result<()> {
    println!(
        "{} Searching for: {}",
        style("🔎").cyan(),
        style(&args.query).yellow().bold()
    );
    println!("Engine: {}", style(&args.engine).cyan());
    let client = HttpClient::new()?;
    let results = match args.engine.as_str() {
        "duckduckgo" => search_duckduckgo(&client, &args.query, args.limit).await?,
        "google" => search_google(&client, &args.query, args.limit).await?,
        "bing" => search_bing(&client, &args.query, args.limit).await?,
        _ => {
            println!("{} Unsupported search engine", style("✗").red());
            return Ok(());
        }
    };
    display_results(&results);
    if args.deep {
        println!("\n{} Deep web search enabled", style("🌐").cyan());
        let deep_results = search_deep_web(&client, &args.query).await?;
        if !deep_results.is_empty() {
            println!("\n{}", style("Deep Web Results:").magenta().bold());
            display_results(&deep_results);
        }
    }
    Ok(())
}
async fn search_duckduckgo(
    client: &HttpClient,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let mut results = vec![];
    let encoded_query = urlencoding::encode(query);
    let url = format!("https://html.duckduckgo.com/html/?q={}", encoded_query);
    let html = client.get(&url).await?;
    let document = Html::parse_document(&html);
    let result_selector = Selector::parse(".result").unwrap();
    let title_selector = Selector::parse(".result__title").unwrap();
    let snippet_selector = Selector::parse(".result__snippet").unwrap();
    let link_selector = Selector::parse(".result__url").unwrap();
    for (i, element) in document.select(&result_selector).enumerate() {
        if i >= limit {
            break;
        }
        let title = element
            .select(&title_selector)
            .next()
            .map(|e| e.text().collect::<String>())
            .unwrap_or_default()
            .trim()
            .to_string();
        let snippet = element
            .select(&snippet_selector)
            .next()
            .map(|e| e.text().collect::<String>())
            .unwrap_or_default()
            .trim()
            .to_string();
        let url = element
            .select(&link_selector)
            .next()
            .and_then(|e| e.value().attr("href"))
            .unwrap_or("")
            .to_string();
        if !title.is_empty() && !url.is_empty() {
            results.push(SearchResult {
                title,
                url,
                snippet,
                engine: "DuckDuckGo".to_string(),
            });
        }
    }
    Ok(results)
}
async fn search_google(
    client: &HttpClient,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let mut results = vec![];
    let encoded_query = urlencoding::encode(query);
    let url = format!(
        "https://www.google.com/search?q={}&num={}",
        encoded_query, limit
    );
    let html = client.get(&url).await?;
    let document = Html::parse_document(&html);
    let result_selector = Selector::parse("div.g").unwrap();
    let title_selector = Selector::parse("h3").unwrap();
    let snippet_selector = Selector::parse("span.st, div.VwiC3b").unwrap();
    let link_selector = Selector::parse("a").unwrap();
    for element in document.select(&result_selector).take(limit) {
        let title = element
            .select(&title_selector)
            .next()
            .map(|e| e.text().collect::<String>())
            .unwrap_or_default();
        let snippet = element
            .select(&snippet_selector)
            .next()
            .map(|e| e.text().collect::<String>())
            .unwrap_or_default();
        let url = element
            .select(&link_selector)
            .next()
            .and_then(|e| e.value().attr("href"))
            .unwrap_or("")
            .to_string();
        if !title.is_empty() && url.starts_with("http") {
            results.push(SearchResult {
                title,
                url,
                snippet,
                engine: "Google".to_string(),
            });
        }
    }
    Ok(results)
}
async fn search_bing(client: &HttpClient, query: &str, limit: usize) -> Result<Vec<SearchResult>> {
    let mut results = vec![];
    let encoded_query = urlencoding::encode(query);
    let url = format!(
        "https://www.bing.com/search?q={}&count={}",
        encoded_query, limit
    );
    let html = client.get(&url).await?;
    let document = Html::parse_document(&html);
    let result_selector = Selector::parse("li.b_algo").unwrap();
    let title_selector = Selector::parse("h2 a").unwrap();
    let snippet_selector = Selector::parse("p, div.b_caption p").unwrap();
    for element in document.select(&result_selector).take(limit) {
        let title_element = element.select(&title_selector).next();
        let title = title_element
            .as_ref()
            .map(|e| e.text().collect::<String>())
            .unwrap_or_default();
        let url = title_element
            .and_then(|e| e.value().attr("href"))
            .unwrap_or("")
            .to_string();
        let snippet = element
            .select(&snippet_selector)
            .next()
            .map(|e| e.text().collect::<String>())
            .unwrap_or_default();
        if !title.is_empty() && !url.is_empty() {
            results.push(SearchResult {
                title,
                url,
                snippet,
                engine: "Bing".to_string(),
            });
        }
    }
    Ok(results)
}
async fn search_deep_web(_client: &HttpClient, query: &str) -> Result<Vec<SearchResult>> {
    let mut results = vec![];
    results.push(SearchResult {
        title: format!("Ahmia Search: {}", query),
        url: format!("https://ahmia.fi/search/?q={}", urlencoding::encode(query)),
        snippet: "Search on Ahmia for Tor hidden services".to_string(),
        engine: "Deep Web".to_string(),
    });
    results.push(SearchResult {
        title: format!("Torch Search: {}", query),
        url: format!(
            "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query={}",
            urlencoding::encode(query)
        ),
        snippet: "Torch - Tor Search Engine (requires Tor Browser)".to_string(),
        engine: "Deep Web".to_string(),
    });
    Ok(results)
}
fn display_results(results: &[SearchResult]) {
    println!("\n{}", style("Search Results:").green().bold());
    println!("{}", style("═══════════════").cyan());
    for (i, result) in results.iter().enumerate() {
        println!("\n{}. {}", style(i + 1).cyan(), style(&result.title).bold());
        println!(
            "   {} {}",
            style("URL:").yellow(),
            style(&result.url).blue().underlined()
        );
        if !result.snippet.is_empty() {
            println!("   {}", result.snippet);
        }
        println!(
            "   {} {}",
            style("Engine:").yellow(),
            style(&result.engine).cyan()
        );
    }
}
