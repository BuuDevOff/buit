use crate::cli::DorkArgs;
use crate::utils::http::HttpClient;
use anyhow::Result;
use console::style;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct DorkResult {
    pub query: String,
    pub results: Vec<DorkEntry>,
    pub total_found: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkEntry {
    pub title: String,
    pub url: String,
    pub snippet: String,
}
pub async fn run(args: DorkArgs) -> Result<()> {
    println!("{} Running dork search", style("🔍").cyan());
    let dork_query = build_dork_query(&args);
    println!("Query: {}", style(&dork_query).yellow().bold());
    let client = HttpClient::new()?;
    let results = execute_dork(&client, &dork_query).await?;
    display_results(&results);
    Ok(())
}
fn build_dork_query(args: &DorkArgs) -> String {
    let mut query_parts = vec![args.query.clone()];
    if let Some(domain) = &args.domain {
        query_parts.push(format!("site:{}", domain));
    }
    if let Some(filetype) = &args.filetype {
        query_parts.push(format!("filetype:{}", filetype));
    }
    if let Some(inurl) = &args.inurl {
        query_parts.push(format!("inurl:{}", inurl));
    }
    if let Some(intitle) = &args.intitle {
        query_parts.push(format!("intitle:{}", intitle));
    }
    query_parts.join(" ")
}
async fn execute_dork(client: &HttpClient, query: &str) -> Result<DorkResult> {
    let encoded_query = urlencoding::encode(query);
    let url = format!("https://html.duckduckgo.com/html/?q={}", encoded_query);
    let html = client.get(&url).await?;
    let results = parse_dork_results(&html)?;
    Ok(DorkResult {
        query: query.to_string(),
        results: results.clone(),
        total_found: results.len(),
    })
}
fn parse_dork_results(html: &str) -> Result<Vec<DorkEntry>> {
    use scraper::{Html, Selector};
    let mut results = vec![];
    let document = Html::parse_document(html);
    let result_selector = Selector::parse(".result").unwrap();
    let title_selector = Selector::parse(".result__title").unwrap();
    let snippet_selector = Selector::parse(".result__snippet").unwrap();
    let link_selector = Selector::parse(".result__url").unwrap();
    for element in document.select(&result_selector) {
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
            results.push(DorkEntry {
                title,
                url,
                snippet,
            });
        }
    }
    Ok(results)
}
fn display_results(results: &DorkResult) {
    println!("\n{}", style("Dork Results:").green().bold());
    println!("{}", style("═════════════").cyan());
    println!(
        "Found {} results",
        style(results.total_found.to_string()).yellow()
    );
    for (i, entry) in results.results.iter().enumerate() {
        println!("\n{}. {}", style(i + 1).cyan(), style(&entry.title).bold());
        println!(
            "   {} {}",
            style("URL:").yellow(),
            style(&entry.url).blue().underlined()
        );
        if !entry.snippet.is_empty() {
            println!("   {}", entry.snippet);
        }
    }
    println!("\n{}", style("Common Dork Examples:").yellow().bold());
    println!("{}", style("═══════════════════").cyan());
    println!("  • site:example.com filetype:pdf - Find PDFs on a domain");
    println!("  • intitle:\"index of\" - Find directory listings");
    println!("  • inurl:admin - Find admin panels");
    println!("  • filetype:sql - Find SQL files");
    println!("  • ext:log - Find log files");
    println!("  • intext:password filetype:txt - Find password files");
    println!("  • site:*.example.com - Find subdomains");
    println!("  • \"confidential\" filetype:doc - Find confidential documents");
}
