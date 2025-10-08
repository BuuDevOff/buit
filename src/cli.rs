use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(name = "buit")]
#[command(author = "BuuDevOff <contact@buudevoff.fr>")]
#[command(version = "1.0.5")]
#[command(
    about = "BUIT - Buu Undercover Intelligence Toolkit - Advanced OSINT framework for security professionals",
    long_about = "BUIT is a comprehensive Open Source Intelligence (OSINT) toolkit designed for security professionals, researchers, and ethical hackers. This tool provides advanced reconnaissance capabilities for authorized security testing and investigations.

🌟 Star the repo: https://github.com/BuuDevOff/BUIT
🚀 Contribute: https://github.com/BuuDevOff/BUIT
💡 Each module has detailed help: buit <module> --help"
)]
pub struct Cli {
    #[arg(long, help = "Start API server mode")]
    pub api: bool,

    #[arg(long, default_value = "1337", help = "API server port")]
    pub port: u16,
    #[arg(long, default_value = "127.0.0.1", help = "API server host binding")]
    pub host: String,
    #[arg(long, help = "Require Authorization: Bearer <token> for API access")]
    pub api_token: Option<String>,
    #[arg(long, help = "Enable permissive CORS", default_value_t = false)]
    pub cors_permissive: bool,

    #[arg(
        long,
        global = true,
        help = "Output results as JSON",
        conflicts_with = "ndjson"
    )]
    pub json: bool,
    #[arg(
        long,
        global = true,
        help = "Output results as NDJSON",
        conflicts_with = "json"
    )]
    pub ndjson: bool,
    #[arg(
        long,
        global = true,
        help = "Silence non-essential console output",
        default_value_t = false
    )]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}
#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Search for usernames across platforms")]
    Username(UsernameArgs),
    #[command(about = "Check email addresses across services")]
    Email(EmailArgs),
    #[command(about = "Search using various search engines")]
    Search(SearchArgs),
    #[command(about = "Perform dork searches")]
    Dork(DorkArgs),
    #[command(about = "Social media reconnaissance")]
    Social(SocialArgs),
    #[command(about = "Manage configuration and API keys")]
    Config(ConfigArgs),
    #[command(about = "Phone number lookup")]
    Phone(PhoneArgs),
    #[command(about = "IP address analysis")]
    Ip(IpArgs),
    #[command(about = "Domain analysis")]
    Domain(DomainArgs),
    #[command(about = "Check for data leaks")]
    Leaks(LeaksArgs),
    #[command(about = "Extract metadata from files")]
    Metadata(MetadataArgs),
    #[command(about = "Enumerate subdomains")]
    Subdomain(SubdomainArgs),
    #[command(about = "Native service discovery (Shodan-like)")]
    Shodan(ShodanArgs),
    #[command(about = "Port scanning")]
    Portscan(PortscanArgs),
    #[command(about = "WHOIS lookup")]
    Whois(WhoisArgs),
    #[command(about = "Reverse image search")]
    ReverseImage(ReverseImageArgs),
    #[command(about = "GitHub OSINT")]
    Github(GithubArgs),
    #[command(about = "Hash identification and cracking")]
    Hash(HashArgs),
    #[command(about = "URL scanning")]
    Urlscan(UrlscanArgs),
    #[command(about = "Wayback Machine lookup")]
    Wayback(WaybackArgs),
    #[command(about = "GeoIP location")]
    Geoip(GeoipArgs),
    #[command(about = "Generate report")]
    Report(ReportArgs),
    #[command(about = "Interactive mode")]
    Interactive,
    #[command(about = "Setup BUIT installation")]
    Setup,

    // New high-priority modules
    #[command(about = "Reverse DNS lookup")]
    ReverseDns(ReverseDnsArgs),
    #[command(about = "ASN lookup")]
    AsnLookup(AsnLookupArgs),
    #[command(about = "SSL certificate analysis")]
    SslCert(SslCertArgs),
    #[command(about = "Breach database check")]
    BreachCheck(BreachCheckArgs),
    #[command(about = "Update BUIT to latest version")]
    Update(UpdateArgs),
    #[cfg(debug_assertions)]
    #[command(about = "(debug) Run quick health-checks across core modules")]
    Check(CheckArgs),
}
#[derive(Parser, Clone)]
pub struct UsernameArgs {
    #[arg(help = "Username to search for")]
    pub username: String,
    #[arg(
        short,
        long,
        help = "Output format (json, csv, text)",
        default_value = "text"
    )]
    pub format: String,
    #[arg(short, long, help = "Output file")]
    pub output: Option<String>,
    #[arg(short, long, help = "Platforms to search (comma-separated)")]
    pub platforms: Option<String>,
}
#[derive(Parser, Clone)]
pub struct EmailArgs {
    #[arg(help = "Email address to check")]
    pub email: String,
    #[arg(short, long, help = "Check for data breaches")]
    pub breaches: bool,
    #[arg(short, long, help = "Check social media accounts")]
    pub social: bool,
    #[arg(
        short,
        long,
        help = "Output format (json, csv, text)",
        default_value = "text"
    )]
    pub format: String,
}
#[derive(Parser, Clone)]
pub struct SearchArgs {
    #[arg(help = "Search query")]
    pub query: String,
    #[arg(
        short,
        long,
        help = "Search engine (duckduckgo, google, bing)",
        default_value = "duckduckgo"
    )]
    pub engine: String,
    #[arg(short, long, help = "Number of results", default_value = "20")]
    pub limit: usize,
    #[arg(short, long, help = "Include deep web results")]
    pub deep: bool,
}
#[derive(Parser, Clone)]
pub struct DorkArgs {
    #[arg(help = "Dork query")]
    pub query: String,
    #[arg(short, long, help = "Target domain")]
    pub domain: Option<String>,
    #[arg(short, long, help = "File type to search")]
    pub filetype: Option<String>,
    #[arg(short, long, help = "Search in URL")]
    pub inurl: Option<String>,
    #[arg(short, long, help = "Search in title")]
    pub intitle: Option<String>,
}
#[derive(Parser, Clone)]
pub struct SocialArgs {
    #[arg(help = "Target identifier (username, email, or phone)")]
    pub target: String,
    #[arg(
        short,
        long,
        help = "Type of identifier (username, email, phone)",
        default_value = "username"
    )]
    pub id_type: String,
    #[arg(short, long, help = "Platforms to search (comma-separated)")]
    pub platforms: Option<String>,
    #[arg(short, long, help = "Include profile analysis")]
    pub analyze: bool,
}
#[derive(Parser, Clone)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}
#[derive(Subcommand, Clone)]
pub enum ConfigAction {
    #[command(about = "Set an API key")]
    SetKey {
        #[arg(help = "Service name")]
        service: String,
        #[arg(help = "API key")]
        key: String,
        #[arg(
            long,
            help = "Store in operating system keychain",
            default_value_t = false
        )]
        secure: bool,
    },
    #[command(about = "Set proxy configuration")]
    SetProxy {
        #[arg(help = "Proxy URL (e.g., http://proxy.example.com:8080)")]
        url: String,
        #[arg(short, long, help = "Proxy username")]
        username: Option<String>,
        #[arg(short, long, help = "Proxy password")]
        password: Option<String>,
    },
    #[command(about = "Set user agent")]
    SetUserAgent {
        #[arg(
            help = "User agent preset (chrome, firefox, safari, edge, mobile, bot) or custom string"
        )]
        agent: String,
    },
    #[command(about = "Set thread count")]
    SetThreads {
        #[arg(help = "Number of threads")]
        count: usize,
    },
    #[command(about = "List configured services")]
    List,
    #[command(about = "Test API keys")]
    Test {
        #[arg(help = "Service to test")]
        service: Option<String>,
    },
    #[command(about = "Set auto-update settings", name = "autoupdate")]
    SetAutoUpdate {
        #[arg(help = "Enable or disable auto-update (on/off)")]
        enabled: String,
    },
}
#[derive(Parser, Clone)]
pub struct PhoneArgs {
    #[arg(help = "Phone number to lookup")]
    pub number: String,
    #[arg(short, long, help = "Include carrier information")]
    pub carrier: bool,
    #[arg(short, long, help = "Output format")]
    pub format: Option<String>,
}
#[derive(Parser, Clone)]
pub struct IpArgs {
    #[arg(help = "IP address to analyze")]
    pub ip: String,
    #[arg(long, help = "Skip reverse DNS lookup", action = clap::ArgAction::SetTrue)]
    pub no_reverse: bool,
    #[arg(long, help = "Skip ASN information", action = clap::ArgAction::SetTrue)]
    pub no_asn: bool,
    #[arg(long, help = "Skip geolocation", action = clap::ArgAction::SetTrue)]
    pub no_geo: bool,
}
#[derive(Parser, Clone)]
pub struct DomainArgs {
    #[arg(help = "Domain to analyze")]
    pub domain: String,
    #[arg(short, long, help = "Include DNS records")]
    pub dns: bool,
    #[arg(short, long, help = "Include SSL certificate info")]
    pub ssl: bool,
    #[arg(short, long, help = "Include WHOIS information")]
    pub whois: bool,
}

#[cfg(debug_assertions)]
#[derive(Parser, Clone)]
pub struct CheckArgs {
    #[arg(
        value_name = "TOKENS",
        help = "Sequence of values tagged with //username, //ip, //domaine (e.g. 'buit check buudever //username 8.8.8.8 //ip exemple.com //domaine')"
    )]
    pub tokens: Vec<String>,
}
#[derive(Parser, Clone)]
pub struct LeaksArgs {
    #[arg(help = "Email or username to check")]
    pub target: String,
    #[arg(long, help = "Check HaveIBeenPwned")]
    pub hibp: bool,
    #[arg(short, long, help = "Include password dumps")]
    pub passwords: bool,
}
#[derive(Parser, Clone)]
pub struct MetadataArgs {
    #[arg(help = "File path to extract metadata from")]
    pub file: String,
    #[arg(short, long, help = "Output format")]
    pub format: Option<String>,
}
#[derive(Parser, Clone)]
pub struct SubdomainArgs {
    #[arg(help = "Domain to enumerate subdomains")]
    pub domain: String,
    #[arg(short, long, help = "Use certificate transparency")]
    pub crt: bool,
    #[arg(short, long, help = "Use DNS brute force")]
    pub brute: bool,
    #[arg(long, help = "Skip availability testing for faster results")]
    pub skip_alive_check: bool,
}
#[derive(Parser, Clone)]
pub struct ShodanArgs {
    #[arg(help = "Search query (IP addresses and/or service names)")]
    pub query: String,
    #[arg(short, long, help = "Maximum number of results", default_value = "10")]
    pub limit: Option<usize>,
    #[arg(short, long, help = "Include vulnerability scanning (not implemented)")]
    pub vulns: bool,
}
#[derive(Parser, Clone)]
pub struct PortscanArgs {
    #[arg(help = "Target IP or hostname")]
    pub target: String,
    #[arg(short, long, help = "Port range (e.g., 1-1000)")]
    pub ports: Option<String>,
    #[arg(short, long, help = "Scan type (tcp, udp)")]
    pub scan_type: Option<String>,
}
#[derive(Parser, Clone)]
pub struct WhoisArgs {
    #[arg(help = "Domain or IP to lookup")]
    pub target: String,
    #[arg(short, long, help = "Parse output")]
    pub parse: bool,
}
#[derive(Parser, Clone)]
pub struct ReverseImageArgs {
    #[arg(help = "Image URL or file path")]
    pub image: String,
    #[arg(short, long, help = "Search engines to use")]
    pub engines: Option<String>,
}
#[derive(Parser, Clone)]
pub struct GithubArgs {
    #[arg(help = "GitHub username or organization")]
    pub target: String,
    #[arg(short, long, help = "Search for secrets")]
    pub secrets: bool,
    #[arg(short, long, help = "Include repositories")]
    pub repos: bool,
}
#[derive(Parser, Clone)]
pub struct HashArgs {
    #[arg(help = "Hash to identify or crack")]
    pub hash: String,
    #[arg(short, long, help = "Identify hash type")]
    pub identify: bool,
    #[arg(short, long, help = "Attempt to crack")]
    pub crack: bool,
}
#[derive(Parser, Clone)]
pub struct UrlscanArgs {
    #[arg(help = "URL to scan")]
    pub url: String,
    #[arg(short, long, help = "Include screenshot")]
    pub screenshot: bool,
}
#[derive(Parser, Clone)]
pub struct WaybackArgs {
    #[arg(help = "URL to lookup")]
    pub url: String,
    #[arg(short, long, help = "Year filter")]
    pub year: Option<String>,
    #[arg(short, long, help = "Limit results")]
    pub limit: Option<usize>,
}
#[derive(Parser, Clone)]
pub struct GeoipArgs {
    #[arg(help = "IP address to geolocate")]
    pub ip: String,
    #[arg(short, long, help = "Include ISP information")]
    pub isp: bool,
}
#[derive(Parser, Clone)]
pub struct ReportArgs {
    #[arg(help = "Report title")]
    pub title: String,
    #[arg(short, long, help = "Output format (html, markdown, pdf)")]
    pub format: Option<String>,
    #[arg(short, long, help = "Output file")]
    pub output: Option<String>,
    #[arg(long, help = "Generate report from JSON results")]
    pub from_json: Option<String>,
}

// New module argument structs
#[derive(Parser, Clone)]
pub struct ReverseDnsArgs {
    #[arg(help = "IP, CIDR block, or IP range to lookup")]
    pub target: String,
    #[arg(
        short,
        long,
        help = "Number of concurrent threads",
        default_value = "10"
    )]
    pub threads: usize,
    #[arg(long, help = "Force processing of large IP ranges")]
    pub force: bool,
}

#[derive(Parser, Clone)]
pub struct AsnLookupArgs {
    #[arg(help = "IP address or hostname to lookup")]
    pub target: String,
}

#[derive(Parser, Clone)]
pub struct SslCertArgs {
    #[arg(help = "Domain to analyze")]
    pub domain: String,
    #[arg(short, long, help = "Port number", default_value = "443")]
    pub port: u16,
}

#[derive(Parser, Clone)]
pub struct BreachCheckArgs {
    #[arg(help = "Email or username to check")]
    pub target: String,
    #[arg(long, help = "Check HaveIBeenPwned")]
    pub hibp: bool,
    #[arg(long, help = "Check DeHashed")]
    pub dehashed: bool,
    #[arg(long, help = "Check IntelX")]
    pub intelx: bool,
    #[arg(short, long, help = "Check all available sources")]
    pub all: bool,
}

#[derive(Parser, Clone)]
pub struct UpdateArgs {
    #[arg(long, help = "Only check for updates without installing")]
    pub check_only: bool,
    #[arg(long, help = "Automatically confirm update without prompting")]
    pub auto_confirm: bool,
}
