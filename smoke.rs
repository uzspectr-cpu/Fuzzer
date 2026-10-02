use std::process::Command;

#[test]
fn smoke_runs() {
    let status = Command::new(env!("CARGO_BIN_EXE_pcif"))
        .args(["--iterations", "10", "--outdir", "/tmp/pcif_smoke"])
        .status()
        .expect("run pcif");
    assert!(status.success());
}
