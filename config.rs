use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "pcif", version, about = "Page-Cache Integrity Fuzzer")]
pub struct Config {
    /// RNG seed
    #[arg(long, default_value_t = 0xC0FFEE)]
    pub seed: u64,

    /// Number of fuzz iterations
    #[arg(long, default_value_t = 10_000)]
    pub iterations: u64,

    /// Parallel workers (future)
    #[arg(long, default_value_t = 1)]
    pub workers: usize,

    /// Work directory
    #[arg(long, default_value = "/tmp/pcif")]
    pub workdir: PathBuf,

    /// Output directory for findings
    #[arg(long, default_value = "./findings")]
    pub outdir: PathBuf,

    /// Verbose logging
    #[arg(long, default_value_t = false)]
    pub verbose: bool,

    /// Maximum zero-copy ops per program
    #[arg(long, default_value_t = 8)]
    pub max_ops: usize,

    /// Chunk size range for splice
    #[arg(long, default_value_t = 65536)]
    pub max_chunk: usize,

    /// Enable destructive writes (mmap MAP_SHARED writes)
    #[arg(long, default_value_t = true)]
    pub allow_mmap_write: bool,
}
