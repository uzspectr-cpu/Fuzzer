use crate::config::Config;
use crate::oracle::Finding;
use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;

pub fn write_finding(cfg: &Config, f: &Finding) -> Result<()> {
    std::fs::create_dir_all(&cfg.outdir)?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let name = format!("finding_{}_{}.json", ts, sanitize(&format!("{:?}", f.kind)));
    let path = cfg.outdir.join(name);
    let mut file = std::fs::File::create(&path)?;
    serde_json::to_writer_pretty(&mut file, f)?;
    file.write_all(b"\n")?;

    // Also emit a human-readable reproducer snippet
    let repro = cfg.outdir.join(format!("repro_{}_{}.rs", ts, sanitize(&format!("{:?}", f.kind))));
    emit_repro(&repro, f)?;
    eprintln!("[pcif] wrote {} and {}", path.display(), repro.display());
    Ok(())
}

pub fn write_summary(cfg: &Config, findings: &[Finding]) -> Result<()> {
    std::fs::create_dir_all(&cfg.outdir)?;
    let path = cfg.outdir.join("summary.json");
    let mut file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(&mut file, &serde_json::json!({
        "total": findings.len(),
        "kinds": findings.iter().map(|f| format!("{:?}", f.kind)).collect::<Vec<_>>(),
    }))?;
    Ok(())
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect()
}

fn emit_repro(path: &PathBuf, f: &Finding) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    writeln!(file, "// Reproducer for finding: {:?}", f.kind)?;
    writeln!(file, "// {}", f.description)?;
    writeln!(file, "// Evidence: {}", f.evidence)?;
    writeln!(file, "//")?;
    writeln!(file, "// Program:")?;
    writeln!(file, "{:#?}", f.program)?;
    writeln!(file, "//")?;
    writeln!(file, "// Re-run with:")?;
    writeln!(file, "//   pcif --iterations 1 --seed <patched-seed>")?;
    Ok(())
}
