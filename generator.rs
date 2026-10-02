use crate::config::Config;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Endpoint {
    File,
    Pipe,
    Socket(AfKind),
    AlgSocket(AlgSpec),
    MemFd,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AfKind {
    Unix,
    Inet,
    Alg,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AlgSpec {
    pub alg_type: AlgType,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlgType {
    Skcipher,
    Hash,
    Aead,
    Rng,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Op {
    /// splice(from_fd, to_fd, len)
    Splice { from: usize, to: usize, len: usize },
    /// vmsplice(pipe_fd, user_buf_id, len, flags)
    Vmsplice { to: usize, buf_id: u32, len: usize, gift: bool },
    /// sendmsg(alg_fd, buf_id, len)
    SendMsg { to: usize, buf_id: u32, len: usize },
    /// recvmsg(alg_fd, buf_id, len)
    RecvMsg { from: usize, buf_id: u32, len: usize },
    /// copy_file_range(src, dst, len)
    CopyFileRange { src: usize, dst: usize, len: usize },
    /// sendfile(out, in, len)
    SendFile { out: usize, inp: usize, len: usize },
    /// msync a region (flags: SYNC / ASYNC / INVALIDATE)
    Msync { region_id: u32, invalidate: bool },
    /// write to mmap region (if allow_mmap_write)
    MmapWrite { region_id: u32, offset: usize, pattern: u8, len: usize },
    /// fsync/fdatasync on fd
    Fsync { fd: usize, datasync: bool },
    /// posix_fadvise DONTNEED on a region's fd
    FadviseDontNeed { region_id: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    pub endpoints: Vec<Endpoint>,
    pub ops: Vec<Op>,
    pub region_count: u32,
    pub buf_count: u32,
}

pub fn generate(cfg: &Config, iter: u64) -> Program {
    let mut rng = ChaCha20Rng::seed_from_u64(cfg.seed ^ iter.wrapping_mul(0x9E3779B97F4A7C15));

    let ep_count = rng.gen_range(2..=5);
    let mut endpoints = Vec::with_capacity(ep_count);
    for _ in 0..ep_count {
        endpoints.push(random_endpoint(&mut rng));
    }

    // always include AF_ALG sometimes
    if rng.gen_bool(0.5) {
        endpoints.push(Endpoint::AlgSocket(random_alg(&mut rng)));
    }
    // always include a pipe (for splice chains)
    endpoints.push(Endpoint::Pipe);
    // and a memfd (for page-cache target)
    endpoints.push(Endpoint::MemFd);

    let n_ops = rng.gen_range(1..=cfg.max_ops);
    let mut ops = Vec::with_capacity(n_ops);
    for _ in 0..n_ops {
        ops.push(random_op(&mut rng, endpoints.len(), cfg.max_chunk, cfg.allow_mmap_write));
    }

    Program {
        endpoints,
        ops,
        region_count: rng.gen_range(1..=3),
        buf_count: rng.gen_range(1..=4),
    }
}

fn random_endpoint<R: Rng>(rng: &mut R) -> Endpoint {
    match rng.gen_range(0..5) {
        0 => Endpoint::File,
        1 => Endpoint::Pipe,
        2 => Endpoint::MemFd,
        3 => Endpoint::Socket(AfKind::Unix),
        _ => Endpoint::AlgSocket(random_alg(rng)),
    }
}

fn random_alg<R: Rng>(rng: &mut R) -> AlgSpec {
    let (ty, names): (AlgType, &[&str]) = match rng.gen_range(0..4) {
        0 => (AlgType::Skcipher, &["cbc(aes)", "ecb(aes)", "ctr(aes)", "cbc(des3_ede)"]),
        1 => (AlgType::Hash, &["sha256", "sha1", "md5", "sha512", "crc32"]),
        2 => (AlgType::Aead, &["gcm(aes)", "ccm(aes)", "rfc4106(gcm(aes))"]),
        _ => (AlgType::Rng, &["stdrng", "jitterentropy_rng"]),
    };
    let name = names[rng.gen_range(0..names.len())].to_string();
    AlgSpec { alg_type: ty, name }
}

fn random_op<R: Rng>(rng: &mut R, n_ep: usize, max_chunk: usize, allow_write: bool) -> Op {
    let a = || rng.gen_range(0..n_ep);
    let chunk = || rng.gen_range(1..=max_chunk);
    let pick = rng.gen_range(0..10);
    match pick {
        0 => Op::Splice { from: a(), to: a(), len: chunk() },
        1 => Op::Vmsplice { to: a(), buf_id: rng.gen_range(0..4), len: chunk(), gift: rng.gen_bool(0.5) },
        2 => Op::SendMsg { to: a(), buf_id: rng.gen_range(0..4), len: chunk() },
        3 => Op::RecvMsg { from: a(), buf_id: rng.gen_range(0..4), len: chunk() },
        4 => Op::CopyFileRange { src: a(), dst: a(), len: chunk() },
        5 => Op::SendFile { out: a(), inp: a(), len: chunk() },
        6 => Op::Msync { region_id: rng.gen_range(0..3), invalidate: rng.gen_bool(0.5) },
        7 if allow_write => Op::MmapWrite {
            region_id: rng.gen_range(0..3),
            offset: rng.gen_range(0..4096),
            pattern: rng.gen(),
            len: rng.gen_range(1..=4096),
        },
        8 => Op::Fsync { fd: a(), datasync: rng.gen_bool(0.5) },
        _ => Op::FadviseDontNeed { region_id: rng.gen_range(0..3) },
    }
}
