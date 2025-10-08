use crate::cli::HashArgs;
use crate::utils::http::HttpClient;
use anyhow::Result;
use blake3;
use console::style;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
#[derive(Debug, Serialize, Deserialize)]
pub struct HashResult {
    pub hash: String,
    pub identified_types: Vec<HashType>,
    pub crack_result: Option<CrackResult>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct HashType {
    pub name: String,
    pub confidence: u8,
    pub description: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CrackResult {
    pub plaintext: Option<String>,
    pub source: String,
    pub method: String,
}
pub async fn run(args: HashArgs) -> Result<()> {
    println!(
        "{} Hash analysis: {}",
        style("🔒").cyan(),
        style(&args.hash).yellow().bold()
    );
    let client = HttpClient::new()?;
    let mut result = HashResult {
        hash: args.hash.clone(),
        identified_types: vec![],
        crack_result: None,
    };
    if args.identify {
        println!("\n{} Identifying hash type...", style("🔍").cyan());
        result.identified_types = identify_hash(&args.hash);
        display_hash_types(&result.identified_types);
    }
    if args.crack {
        println!("\n{} Attempting to crack hash...", style("⚡").cyan());
        result.crack_result = attempt_crack(&client, &args.hash).await?;
        if let Some(crack_result) = &result.crack_result {
            display_crack_result(crack_result);
        } else {
            println!("{} Hash not found in common databases", style("✗").red());
        }
    }
    Ok(())
}
fn identify_hash(hash: &str) -> Vec<HashType> {
    let mut types = vec![];
    let len = hash.len();
    let hash_lower = hash.to_lowercase();
    let is_hex = hash_lower.chars().all(|c| c.is_ascii_hexdigit());
    match len {
        32 if is_hex => {
            types.push(HashType {
                name: "MD5".to_string(),
                confidence: 90,
                description: "Message Digest Algorithm 5".to_string(),
            });
            types.push(HashType {
                name: "NTLM".to_string(),
                confidence: 80,
                description: "Windows NTLM Hash".to_string(),
            });
        }
        40 if is_hex => {
            types.push(HashType {
                name: "SHA1".to_string(),
                confidence: 95,
                description: "Secure Hash Algorithm 1".to_string(),
            });
        }
        56 if is_hex => {
            types.push(HashType {
                name: "SHA224".to_string(),
                confidence: 90,
                description: "Secure Hash Algorithm 224-bit".to_string(),
            });
        }
        64 if is_hex => {
            types.push(HashType {
                name: "SHA256".to_string(),
                confidence: 95,
                description: "Secure Hash Algorithm 256-bit".to_string(),
            });
            types.push(HashType {
                name: "SHA3-256".to_string(),
                confidence: 85,
                description: "SHA-3 256-bit".to_string(),
            });
        }
        96 if is_hex => {
            types.push(HashType {
                name: "SHA384".to_string(),
                confidence: 95,
                description: "Secure Hash Algorithm 384-bit".to_string(),
            });
        }
        128 if is_hex => {
            types.push(HashType {
                name: "SHA512".to_string(),
                confidence: 95,
                description: "Secure Hash Algorithm 512-bit".to_string(),
            });
        }
        13 => {
            types.push(HashType {
                name: "DES Crypt".to_string(),
                confidence: 85,
                description: "Traditional DES-based crypt(3)".to_string(),
            });
        }
        _ => {
            if hash.starts_with("$1$") {
                types.push(HashType {
                    name: "MD5 Crypt".to_string(),
                    confidence: 95,
                    description: "MD5-based crypt(3)".to_string(),
                });
            } else if hash.starts_with("$2a$")
                || hash.starts_with("$2b$")
                || hash.starts_with("$2y$")
            {
                types.push(HashType {
                    name: "bcrypt".to_string(),
                    confidence: 95,
                    description: "bcrypt password hash".to_string(),
                });
            } else if hash.starts_with("$5$") {
                types.push(HashType {
                    name: "SHA256 Crypt".to_string(),
                    confidence: 95,
                    description: "SHA256-based crypt(3)".to_string(),
                });
            } else if hash.starts_with("$6$") {
                types.push(HashType {
                    name: "SHA512 Crypt".to_string(),
                    confidence: 95,
                    description: "SHA512-based crypt(3)".to_string(),
                });
            } else if hash.starts_with("{SHA}") {
                types.push(HashType {
                    name: "LDAP SHA".to_string(),
                    confidence: 95,
                    description: "LDAP SHA hash".to_string(),
                });
            } else if hash.starts_with("{SSHA}") {
                types.push(HashType {
                    name: "LDAP SSHA".to_string(),
                    confidence: 95,
                    description: "LDAP Salted SHA hash".to_string(),
                });
            } else {
                types.push(HashType {
                    name: "Unknown".to_string(),
                    confidence: 10,
                    description: "Hash type could not be identified".to_string(),
                });
            }
        }
    }
    types
}
async fn attempt_crack(client: &HttpClient, hash: &str) -> Result<Option<CrackResult>> {
    if hash.len() == 32 {
        if let Some(result) = check_md5_database(client, hash).await? {
            return Ok(Some(result));
        }
    }
    if let Some(result) = check_local_tables(hash) {
        return Ok(Some(result));
    }
    if let Some(result) = try_common_passwords(hash) {
        return Ok(Some(result));
    }
    Ok(None)
}
async fn check_md5_database(_client: &HttpClient, hash: &str) -> Result<Option<CrackResult>> {
    let common_hashes = [
        ("5d41402abc4b2a76b9719d911017c592", "hello"),
        ("098f6bcd4621d373cade4e832627b4f6", "test"),
        ("e10adc3949ba59abbe56e057f20f883e", "123456"),
        ("25d55ad283aa400af464c76d713c07ad", "12345678"),
        ("d8578edf8458ce06fbc5bb76a58c5ca4", "qwerty"),
        (
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
            "hello",
        ),
    ];
    for (known_hash, password) in &common_hashes {
        if known_hash.to_lowercase() == hash.to_lowercase() {
            return Ok(Some(CrackResult {
                plaintext: Some(password.to_string()),
                source: "Common Hash Database".to_string(),
                method: "Hash Lookup".to_string(),
            }));
        }
    }
    Ok(None)
}
fn check_local_tables(hash: &str) -> Option<CrackResult> {
    let rainbow_table = [
        ("aab3238922bcc25a6f606eb525ffdc56", "password"),
        ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"),
        ("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"),
    ];
    for (known_hash, password) in &rainbow_table {
        if known_hash.to_lowercase() == hash.to_lowercase() {
            return Some(CrackResult {
                plaintext: Some(password.to_string()),
                source: "Rainbow Table".to_string(),
                method: "Precomputed Hash".to_string(),
            });
        }
    }
    None
}
fn try_common_passwords(hash: &str) -> Option<CrackResult> {
    let common_passwords = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "password123",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
    ];
    for password in &common_passwords {
        // SHA-256 (preferred over MD5)
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let sha256_hash = format!("{:x}", hasher.finalize());
        if sha256_hash == hash.to_lowercase() {
            return Some(CrackResult {
                plaintext: Some(password.to_string()),
                source: "Common Passwords".to_string(),
                method: "Dictionary Attack (SHA-256)".to_string(),
            });
        }

        // BLAKE3 (modern, fast hashing)
        let blake3_hash = format!("{}", blake3::hash(password.as_bytes()));
        if blake3_hash == hash.to_lowercase() {
            return Some(CrackResult {
                plaintext: Some(password.to_string()),
                source: "Common Passwords".to_string(),
                method: "Dictionary Attack (BLAKE3)".to_string(),
            });
        }
    }
    None
}
fn display_hash_types(types: &[HashType]) {
    println!("\n{}", style("Hash Type Analysis:").green().bold());
    println!("{}", style("══════════════════").cyan());
    for hash_type in types {
        let confidence_color = match hash_type.confidence {
            90..=100 => style(hash_type.confidence.to_string()).green(),
            70..=89 => style(hash_type.confidence.to_string()).yellow(),
            _ => style(hash_type.confidence.to_string()).red(),
        };
        println!(
            "  {} {} ({}% confidence)",
            style("•").cyan(),
            style(&hash_type.name).bold(),
            confidence_color
        );
        println!("    {}", style(&hash_type.description).dim());
    }
}
fn display_crack_result(result: &CrackResult) {
    println!("\n{}", style("Crack Results:").green().bold());
    println!("{}", style("══════════════").cyan());
    if let Some(plaintext) = &result.plaintext {
        println!(
            "  {} {}",
            style("Plaintext:").yellow(),
            style(plaintext).green().bold()
        );
        println!(
            "  {} {}",
            style("Source:").yellow(),
            style(&result.source).cyan()
        );
        println!(
            "  {} {}",
            style("Method:").yellow(),
            style(&result.method).cyan()
        );
    }
}
