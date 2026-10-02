use crate::config::Config;
use crate::generator::*;
use anyhow::{anyhow, Context, Result};
use nix::fcntl::{splice, SpliceFFlags};
use nix::sys::mman::{mmap, msync, munmap, MapFlags, MsFlags, ProtFlags};
use nix::sys::socket::{
    accept, bind, listen, recv, send, socket, AddressFamily, SockFlag, SockType, UnixAddr,
};
use nix::sys::stat::Mode;
use nix::unistd::{close, ftruncate, pipe, read, write, Pid};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::ptr;

#[derive(Debug, Clone)]
pub struct RegionSnapshot {
    pub region_id: u32,
    pub pre: Vec<u8>,
    pub post: Vec<u8>,
    pub pre_hash: [u8; 32],
    pub post_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Trace {
    pub op_results: Vec<OpResult>,
    pub regions: Vec<RegionSnapshot>,
    pub files: Vec<FileSnapshot>,
}

#[derive(Debug, Clone)]
pub struct OpResult {
    pub idx: usize,
    pub ok: bool,
    pub ret: i64,
    pub errno: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub pre_hash: [u8; 32],
    pub post_hash: [u8; 32],
    pub pre: Vec<u8>,
    pub post: Vec<u8>,
}

struct FdTable {
    fds: HashMap<usize, OwnedFd>,
    paths: HashMap<usize, PathBuf>,
    alg_fds: HashMap<usize, (AlgType, String)>,
}

impl FdTable {
    fn new() -> Self {
        Self { fds: HashMap::new(), paths: HashMap::new(), alg_fds: HashMap::new() }
    }
    fn get(&self, idx: usize) -> Result<RawFd> {
        self.fds.get(&idx).map(|f| f.as_raw_fd())
            .ok_or_else(|| anyhow!("no fd at idx {}", idx))
    }
}

pub fn run(cfg: &Config, prog: &Program) -> Result<Trace> {
    let run_dir = cfg.workdir.join(format!("run_{}", std::process::id()));
    std::fs::create_dir_all(&run_dir)?;

    let mut table = FdTable::new();

    // --- open endpoints ---
    for (i, ep) in prog.endpoints.iter().enumerate() {
        match ep {
            Endpoint::File => {
                let p = run_dir.join(format!("file_{}", i));
                std::fs::write(&p, b"pcif-initial-contents-0123456789abcdef")?;
                let f = std::fs::OpenOptions::new()
                    .read(true).write(true).open(&p)?;
                table.paths.insert(i, p);
                table.fds.insert(i, OwnedFd::from(f));
            }
            Endpoint::MemFd => {
                let name = CString::new(format!("pcif_memfd_{}", i))?;
                let raw = unsafe {
                    libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC)
                };
                if raw < 0 { return Err(anyhow!("memfd_create failed")); }
                let f = unsafe { OwnedFd::from_raw_fd(raw) };
                ftruncate(&f, 65536)?;
                table.fds.insert(i, f);
            }
            Endpoint::Pipe => {
                let (r, w) = pipe()?;
                // use write end as the main handle
                drop(r);
                table.fds.insert(i, w);
            }
            Endpoint::Socket(AfKind::Unix) => {
                let (a, _b) = socketpair_unix()?;
                table.fds.insert(i, a);
            }
            Endpoint::Socket(AfKind::Inet) => {
                let s = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None)?;
                table.fds.insert(i, s);
            }
            Endpoint::AlgSocket(spec) => {
                let fd = open_alg(spec)?;
                table.alg_fds.insert(i, (spec.alg_type, spec.name.clone()));
                table.fds.insert(i, fd);
            }
            Endpoint::Socket(AfKind::Alg) => {
                let fd = open_alg(&AlgSpec { alg_type: AlgType::Hash, name: "sha256".into() })?;
                table.fds.insert(i, fd);
            }
        }
    }

    // --- setup mmap regions for memfd/file endpoints ---
    let mut regions: Vec<MmapRegion> = Vec::new();
    for (i, ep) in prog.endpoints.iter().enumerate() {
        if matches!(ep, Endpoint::MemFd | Endpoint::File) {
            let fd = table.get(i)?;
            let len = 65536;
            let prot = if cfg.allow_mmap_write {
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
            } else {
                ProtFlags::PROT_READ
            };
            let ptr = unsafe {
                mmap(None, len.try_into().unwrap(), prot, MapFlags::MAP_SHARED, fd, 0)
            }.context("mmap")?;
            regions.push(MmapRegion { region_id: regions.len() as u32, fd_idx: i, ptr, len });
        }
    }

    // --- pre snapshots ---
    let pre_regions = snapshot_regions(&regions)?;
    let pre_files = snapshot_files(&table.paths)?;

    // --- execute ops ---
    let mut op_results = Vec::new();
    for (idx, op) in prog.ops.iter().enumerate() {
        let res = exec_op(op, &mut table, &regions, prog);
        op_results.push(OpResult {
            idx,
            ok: res.is_ok(),
            ret: res.as_ref().copied().unwrap_or(-1),
            errno: res.err().map(|e| e as i32),
        });
    }

    // --- post snapshots ---
    let post_regions = snapshot_regions(&regions)?;
    let post_files = snapshot_files(&table.paths)?;

    // --- build trace ---
    let mut region_snaps = Vec::new();
    for (i, (pre, post)) in pre_regions.iter().zip(post_regions.iter()).enumerate() {
        region_snaps.push(RegionSnapshot {
            region_id: regions[i].region_id,
            pre: pre.clone(), post: post.clone(),
            pre_hash: blake3::hash(pre).into(),
            post_hash: blake3::hash(post).into(),
        });
    }
    let mut file_snaps = Vec::new();
    for ((path, pre), post) in pre_files.iter().zip(post_files.iter()) {
        file_snaps.push(FileSnapshot {
            path: path.clone(),
            pre_hash: blake3::hash(pre).into(),
            post_hash: blake3::hash(post).into(),
            pre: pre.clone(), post: post.clone(),
        });
    }

    // cleanup
    for r in &regions {
        unsafe { let _ = munmap(r.ptr, r.len); }
    }
    drop(table);
    let _ = std::fs::remove_dir_all(&run_dir);

    Ok(Trace {
        op_results,
        regions: region_snaps,
        files: file_snaps,
    })
}

struct MmapRegion {
    region_id: u32,
    fd_idx: usize,
    ptr: *mut libc::c_void,
    len: usize,
}

unsafe impl Send for MmapRegion {}

fn snapshot_regions(regions: &[MmapRegion]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for r in regions {
        let mut v = vec![0u8; r.len];
        unsafe {
            ptr::copy_nonoverlapping(r.ptr as *const u8, v.as_mut_ptr(), r.len);
        }
        out.push(v);
    }
    Ok(out)
}

fn snapshot_files(paths: &HashMap<usize, PathBuf>) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut v: Vec<_> = paths.iter().collect();
    v.sort_by_key(|(k, _)| **k);
    let mut out = Vec::new();
    for (_, p) in v {
        let data = std::fs::read(p).unwrap_or_default();
        out.push((p.clone(), data));
    }
    Ok(out)
}

fn exec_op(
    op: &Op,
    table: &mut FdTable,
    regions: &[MmapRegion],
    prog: &Program,
) -> Result<i64, nix::errno::Errno> {
    match op {
        Op::Splice { from, to, len } => {
            let fi = table.get(*from).map_err(|_| nix::errno::Errno::EBADF)?;
            let ti = table.get(*to).map_err(|_| nix::errno::Errno::EBADF)?;
            let n = splice(fi, None, ti, None, *len, SpliceFFlags::empty())?;
            Ok(n as i64)
        }
        Op::Vmsplice { to, buf_id, len, gift } => {
            let fd = table.get(*to).map_err(|_| nix::errno::Errno::EBADF)?;
            // build iovec from a stack buffer
            let mut buf = vec![*buf_id as u8; (*len).min(65536)];
            let iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let flags = if *gift { libc::SPLICE_F_GIFT } else { 0 };
            let n = unsafe { libc::vmsplice(fd, &iov, 1, flags) };
            if n < 0 { return Err(nix::errno::Errno::last()); }
            Ok(n as i64)
        }
        Op::SendMsg { to, buf_id, len } => {
            let fd = table.get(*to).map_err(|_| nix::errno::Errno::EBADF)?;
            let buf = vec![*buf_id as u8; (*len).min(65536)];
            let n = send(fd, &buf, nix::sys::socket::MsgFlags::empty())?;
            Ok(n as i64)
        }
        Op::RecvMsg { from, buf_id: _, len } => {
            let fd = table.get(*from).map_err(|_| nix::errno::Errno::EBADF)?;
            let mut buf = vec![0u8; (*len).min(65536)];
            let n = recv(fd, &mut buf, nix::sys::socket::MsgFlags::empty())?;
            Ok(n as i64)
        }
        Op::CopyFileRange { src, dst, len } => {
            let s = table.get(*src).map_err(|_| nix::errno::Errno::EBADF)?;
            let d = table.get(*dst).map_err(|_| nix::errno::Errno::EBADF)?;
            let n = unsafe {
                libc::copy_file_range(s, ptr::null_mut(), d, ptr::null_mut(), *len, 0)
            };
            if n < 0 { return Err(nix::errno::Errno::last()); }
            Ok(n as i64)
        }
        Op::SendFile { out, inp, len } => {
            let o = table.get(*out).map_err(|_| nix::errno::Errno::EBADF)?;
            let i = table.get(*inp).map_err(|_| nix::errno::Errno::EBADF)?;
            let n = unsafe { libc::sendfile(o, i, ptr::null_mut(), *len) };
            if n < 0 { return Err(nix::errno::Errno::last()); }
            Ok(n as i64)
        }
        Op::Msync { region_id, invalidate } => {
            let r = regions.iter().find(|r| r.region_id == *region_id)
                .ok_or(nix::errno::Errno::EINVAL)?;
            let flags = if *invalidate { MsFlags::MS_INVALIDATE } else { MsFlags::MS_SYNC };
            msync(r.ptr, r.len, flags)?;
            Ok(0)
        }
        Op::MmapWrite { region_id, offset, pattern, len } => {
            let r = regions.iter().find(|r| r.region_id == *region_id)
                .ok_or(nix::errno::Errno::EINVAL)?;
            if *offset + *len > r.len { return Err(nix::errno::Errno::EINVAL); }
            unsafe {
                let base = (r.ptr as *mut u8).add(*offset);
                ptr::write_bytes(base, *pattern, *len);
            }
            Ok(*len as i64)
        }
        Op::Fsync { fd, datasync } => {
            let f = table.get(*fd).map_err(|_| nix::errno::Errno::EBADF)?;
            let r = unsafe {
                if *datasync { libc::fdatasync(f) } else { libc::fsync(f) }
            };
            if r < 0 { return Err(nix::errno::Errno::last()); }
            Ok(0)
        }
        Op::FadviseDontNeed { region_id } => {
            let r = regions.iter().find(|r| r.region_id == *region_id)
                .ok_or(nix::errno::Errno::EINVAL)?;
            let f = table.get(r.fd_idx).map_err(|_| nix::errno::Errno::EBADF)?;
            let rc = unsafe {
                libc::posix_fadvise(f, 0, r.len as i64, libc::POSIX_FADV_DONTNEED)
            };
            if rc != 0 { return Err(nix::errno::Errno::from_raw(rc)); }
            Ok(0)
        }
    }
}

fn socketpair_unix() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
    };
    if rc < 0 { return Err(anyhow!("socketpair")); }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn open_alg(spec: &AlgSpec) -> Result<OwnedFd> {
    let s = socket(AddressFamily::Alg, SockType::SeqPacket, SockFlag::empty(), None)
        .context("socket AF_ALG")?;
    let type_str = match spec.alg_type {
        AlgType::Skcipher => "skcipher",
        AlgType::Hash => "hash",
        AlgType::Aead => "aead",
        AlgType::Rng => "rng",
    };
    // bind via raw sockaddr_alg (bypasses nix's AlgAddr limitations)
    #[repr(C)]
    struct SockAddrAlg {
        salg_family: u16,
        salg_type: [u8; 64],
        salg_feat: u32,
        salg_mask: u32,
        salg_name: [u8; 64],
    }
    let mut sa: SockAddrAlg = unsafe { std::mem::zeroed() };
    sa.salg_family = libc::AF_ALG as u16;
    let t = type_str.as_bytes();
    let n = spec.name.as_bytes();
    sa.salg_type[..t.len()].copy_from_slice(t);
    sa.salg_name[..n.len()].copy_from_slice(n);

    let rc = unsafe {
        libc::bind(
            s.as_raw_fd(),
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<SockAddrAlg>() as u32,
        )
    };
    if rc < 0 {
        let e = nix::errno::Errno::last();
        return Err(anyhow!("bind AF_ALG {} {}: {}", type_str, spec.name, e));
    }
    Ok(s)
}
