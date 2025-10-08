use crate::cli::ReportArgs;
use anyhow::Result;
use chrono::Utc;
use console::style;
use handlebars::Handlebars;
use serde_json::{json, Value};
use std::fs;

pub fn run(args: ReportArgs) -> Result<()> {
    println!(
        "{} Generating report: {}",
        style("📊").cyan(),
        style(&args.title).yellow().bold()
    );

    let format = args.format.as_deref().unwrap_or("html");
    let output_file = args.output.as_deref().unwrap_or_else(|| match format {
        "html" => "report.html",
        "markdown" => "report.md",
        "pdf" => "report.pdf",
        _ => "report.html",
    });

    println!("📄 Format: {}", style(format).cyan());
    println!("💾 Output: {}", style(output_file).yellow());

    let report_data = generate_sample_report_data(&args.title)?;

    match format {
        "html" => generate_html_report(&report_data, output_file)?,
        "markdown" => generate_markdown_report(&report_data, output_file)?,
        "pdf" => {
            println!(
                "{} PDF generation not implemented yet, generating HTML instead",
                style("⚠️").yellow()
            );
            generate_html_report(&report_data, &output_file.replace(".pdf", ".html"))?;
        }
        _ => {
            println!(
                "{} Unknown format '{}', using HTML",
                style("⚠️").yellow(),
                format
            );
            generate_html_report(&report_data, output_file)?;
        }
    }

    println!(
        "\n{} Report generated successfully: {}",
        style("✅").green(),
        style(style(output_file).green()).bold()
    );

    Ok(())
}

fn generate_sample_report_data(title: &str) -> Result<Value> {
    let now = Utc::now();

    Ok(json!({
        "title": title,
        "generated_at": now.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        "generated_by": "BUIT - Buu Undercover Intelligence Toolkit",
        "version": "1.0.2",
        "summary": {
            "total_checks": 15,
            "successful": 12,
            "warnings": 2,
            "errors": 1
        },
        "sections": [
            {
                "title": "Domain Analysis",
                "status": "completed",
                "findings": [
                    {
                        "type": "info",
                        "title": "SSL Certificate",
                        "description": "Valid SSL certificate found",
                        "details": "Certificate expires in 85 days"
                    },
                    {
                        "type": "warning",
                        "title": "DNS Configuration",
                        "description": "Missing SPF record",
                        "details": "No SPF record found, emails may be marked as spam"
                    }
                ]
            },
            {
                "title": "Port Scan Results",
                "status": "completed",
                "findings": [
                    {
                        "type": "info",
                        "title": "Open Ports",
                        "description": "3 open ports detected",
                        "details": "Ports 22, 80, 443 are open"
                    },
                    {
                        "type": "success",
                        "title": "Security",
                        "description": "No dangerous ports exposed",
                        "details": "Common administrative ports are properly secured"
                    }
                ]
            },
            {
                "title": "Subdomain Enumeration",
                "status": "completed",
                "findings": [
                    {
                        "type": "info",
                        "title": "Subdomains Found",
                        "description": "8 subdomains discovered",
                        "details": "www, api, mail, ftp, admin, dev, staging, cdn"
                    }
                ]
            }
        ],
        "recommendations": [
            "Configure SPF record for better email deliverability",
            "Consider implementing DMARC policy",
            "Review subdomain security policies",
            "Monitor SSL certificate expiration dates"
        ],
        "raw_data": {
            "scan_duration": "4 minutes 32 seconds",
            "targets_scanned": 1,
            "total_requests": 247
        }
    }))
}

fn generate_html_report(data: &Value, output_file: &str) -> Result<()> {
    let template = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}} - OSINT Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .meta {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-item {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .section-header {
            background: #667eea;
            color: white;
            padding: 20px;
            font-size: 1.2em;
            font-weight: bold;
        }
        .section-content {
            padding: 20px;
        }
        .finding {
            border-left: 4px solid #ddd;
            padding: 15px;
            margin: 15px 0;
            background: #f9f9f9;
        }
        .finding.info { border-left-color: #3498db; }
        .finding.success { border-left-color: #2ecc71; }
        .finding.warning { border-left-color: #f39c12; }
        .finding.error { border-left-color: #e74c3c; }
        .finding h4 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .finding p {
            margin: 5px 0;
            color: #666;
        }
        .recommendations {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .recommendations h3 {
            color: #667eea;
            margin-top: 0;
        }
        .recommendations ul {
            list-style: none;
            padding: 0;
        }
        .recommendations li {
            padding: 10px;
            margin: 5px 0;
            background: #f8f9fa;
            border-left: 4px solid #f39c12;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{title}}</h1>
        <p>OSINT Security Report</p>
    </div>
    
    <div class="meta">
        <p><strong>Generated:</strong> {{generated_at}}</p>
        <p><strong>Tool:</strong> {{generated_by}} v{{version}}</p>
        <p><strong>Duration:</strong> {{raw_data.scan_duration}}</p>
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <div class="summary-number">{{summary.total_checks}}</div>
            <div>Total Checks</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{{summary.successful}}</div>
            <div>Successful</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{{summary.warnings}}</div>
            <div>Warnings</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{{summary.errors}}</div>
            <div>Errors</div>
        </div>
    </div>
    
    {{#each sections}}
    <div class="section">
        <div class="section-header">{{title}}</div>
        <div class="section-content">
            {{#each findings}}
            <div class="finding {{type}}">
                <h4>{{title}}</h4>
                <p><strong>{{description}}</strong></p>
                <p>{{details}}</p>
            </div>
            {{/each}}
        </div>
    </div>
    {{/each}}
    
    <div class="recommendations">
        <h3>🔍 Recommendations</h3>
        <ul>
            {{#each recommendations}}
            <li>{{this}}</li>
            {{/each}}
        </ul>
    </div>
    
    <div class="footer">
        <p>Report generated by BUIT (Buu Undercover Intelligence Toolkit)</p>
        <p>For authorized security testing and research purposes only</p>
    </div>
</body>
</html>
"#;

    let mut handlebars = Handlebars::new();
    handlebars.register_template_string("report", template)?;

    let html = handlebars.render("report", data)?;
    fs::write(output_file, html)?;

    Ok(())
}

fn generate_markdown_report(data: &Value, output_file: &str) -> Result<()> {
    let mut content = String::new();

    // Header
    content.push_str(&format!(
        "# {}\n\n",
        data["title"].as_str().unwrap_or("OSINT Report")
    ));
    content.push_str("**OSINT Security Report**\n\n");

    // Metadata
    content.push_str("## 📋 Report Information\n\n");
    content.push_str(&format!(
        "- **Generated:** {}\n",
        data["generated_at"].as_str().unwrap_or("Unknown")
    ));
    content.push_str(&format!(
        "- **Tool:** {} v{}\n",
        data["generated_by"].as_str().unwrap_or("BUIT"),
        data["version"].as_str().unwrap_or("1.0.2")
    ));
    content.push_str(&format!(
        "- **Duration:** {}\n\n",
        data["raw_data"]["scan_duration"]
            .as_str()
            .unwrap_or("Unknown")
    ));

    // Summary
    content.push_str("## 📊 Summary\n\n");
    if let Some(summary) = data["summary"].as_object() {
        content.push_str("| Metric | Count |\n");
        content.push_str("|--------|-------|\n");
        for (key, value) in summary {
            content.push_str(&format!(
                "| {} | {} |\n",
                key.replace('_', " ").to_uppercase(),
                value.as_u64().unwrap_or(0)
            ));
        }
    }
    content.push_str("\n");

    // Sections
    if let Some(sections) = data["sections"].as_array() {
        for section in sections {
            content.push_str(&format!(
                "## 🔍 {}\n\n",
                section["title"].as_str().unwrap_or("Section")
            ));

            if let Some(findings) = section["findings"].as_array() {
                for finding in findings {
                    let icon = match finding["type"].as_str().unwrap_or("info") {
                        "success" => "✅",
                        "warning" => "⚠️",
                        "error" => "❌",
                        _ => "ℹ️",
                    };

                    content.push_str(&format!(
                        "### {} {}\n\n",
                        icon,
                        finding["title"].as_str().unwrap_or("Finding")
                    ));
                    content.push_str(&format!(
                        "**{}**\n\n",
                        finding["description"].as_str().unwrap_or("")
                    ));
                    content.push_str(&format!(
                        "{}\n\n",
                        finding["details"].as_str().unwrap_or("")
                    ));
                }
            }
        }
    }

    // Recommendations
    content.push_str("## 💡 Recommendations\n\n");
    if let Some(recommendations) = data["recommendations"].as_array() {
        for rec in recommendations {
            content.push_str(&format!("- {}\n", rec.as_str().unwrap_or("")));
        }
    }

    content.push_str("\n---\n\n");
    content.push_str("*Report generated by BUIT (Buu Undercover Intelligence Toolkit)*\n");
    content.push_str("*For authorized security testing and research purposes only*\n");

    fs::write(output_file, content)?;

    Ok(())
}
