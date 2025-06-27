use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use chrono::{DateTime, Local, Utc};

use crate::config::read_history;

use printpdf::{BuiltinFont, Mm, Op, PdfDocument, PdfPage, PdfSaveOptions, Point, Pt, TextItem};

/// Representation of a single backup for compliance analysis
pub struct ComplianceEntry {
    pub backup: String,
    pub timestamp: DateTime<Utc>,
    pub age_days: i64,
    pub encrypted: bool,
}

/// Scan stored history and collect compliance data
pub fn gather_metadata() -> Result<Vec<ComplianceEntry>, Box<dyn Error>> {
    let history = read_history().unwrap_or_default();
    let now = Utc::now();
    let mut out = Vec::new();
    for h in history {
        let ts = DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(h.timestamp as u64));
        let age_days = now.signed_duration_since(ts).num_days();
        let encrypted = h.backup.ends_with(".enc");
        out.push(ComplianceEntry {
            backup: h.backup,
            timestamp: ts,
            age_days,
            encrypted,
        });
    }
    Ok(out)
}

fn html_table(entries: &[ComplianceEntry]) -> String {
    let mut html = String::from("<html><head><title>Backup Compliance Report</title></head><body>");
    html.push_str("<h1>Backup Compliance Report</h1><table border=\"1\"><tr><th>Backup</th><th>Date</th><th>Age (days)</th><th>Encrypted</th></tr>");
    for e in entries {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            e.backup,
            e.timestamp
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S"),
            e.age_days,
            if e.encrypted { "Yes" } else { "No" }
        ));
    }
    html.push_str("</table></body></html>");
    html
}

fn write_html(entries: &[ComplianceEntry], path: &Path) -> Result<(), Box<dyn Error>> {
    fs::write(path, html_table(entries))?;
    Ok(())
}

fn write_pdf(entries: &[ComplianceEntry], path: &Path) -> Result<(), Box<dyn Error>> {
    let mut doc = PdfDocument::new("Backup Compliance Report");
    let mut ops = Vec::<Op>::new();
    ops.push(Op::SaveGraphicsState);
    ops.push(Op::StartTextSection);
    ops.push(Op::SetTextCursor {
        pos: Point::new(Mm(20.0), Mm(270.0)),
    });
    ops.push(Op::SetFontSizeBuiltinFont {
        size: Pt(18.0),
        font: BuiltinFont::HelveticaBold,
    });
    ops.push(Op::SetLineHeight { lh: Pt(18.0) });
    ops.push(Op::WriteTextBuiltinFont {
        items: vec![TextItem::Text("Backup Compliance Report".into())],
        font: BuiltinFont::HelveticaBold,
    });
    ops.push(Op::AddLineBreak);
    ops.push(Op::SetFontSizeBuiltinFont {
        size: Pt(12.0),
        font: BuiltinFont::Helvetica,
    });
    ops.push(Op::SetLineHeight { lh: Pt(12.0) });
    for e in entries {
        let line = format!(
            "{} | {} | {} days | encrypted: {}",
            e.backup,
            e.timestamp.with_timezone(&Local).format("%Y-%m-%d"),
            e.age_days,
            if e.encrypted { "yes" } else { "no" }
        );
        ops.push(Op::WriteTextBuiltinFont {
            items: vec![TextItem::Text(line)],
            font: BuiltinFont::Helvetica,
        });
        ops.push(Op::AddLineBreak);
    }
    ops.push(Op::EndTextSection);
    ops.push(Op::RestoreGraphicsState);
    let page = PdfPage::new(Mm(210.0), Mm(297.0), ops);
    let bytes = doc
        .with_pages(vec![page])
        .save(&PdfSaveOptions::default(), &mut Vec::new());
    fs::write(path, bytes)?;
    Ok(())
}

/// Generate both HTML and PDF reports in the given directory
pub fn generate_reports(output: &str) -> Result<(), Box<dyn Error>> {
    let entries = gather_metadata()?;
    if entries.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(output)?;
    let html_path = Path::new(output).join("compliance_report.html");
    write_html(&entries, &html_path)?;
    let pdf_path = Path::new(output).join("compliance_report.pdf");
    write_pdf(&entries, &pdf_path)?;
    println!("Compliance reports written to {}", output);
    Ok(())
}
