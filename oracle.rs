use crate::config::Config;
use crate::executor::Trace;
use crate::generator::{Op, Program};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingKind {
    /// Region changed after a read-only-only op sequence
    ReadOnlyMutation,
    /// Region changed but no successful writer op was recorded
    GhostWrite,
    /// Region content differs from file content despite msync
    MsyncDivergence,
    /// Hash mismatch between two snapshots of the same region
    SnapshotHashMismatch,
    /// Op returned success but had no observable effect where one is expected
    SilentNoOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub program: Program,
    pub description: String,
    pub evidence: String,
}

pub fn check(_cfg: &Config, prog: &Program, trace: &Trace) -> Option<Finding> {
    // Rule 1: any region whose hash changed without a corresponding successful writer op
    let has_writer = prog.ops.iter().any(|op| matches!(op,
        Op::Splice { .. } | Op::Vmsplice { .. } | Op::SendMsg { .. }
        | Op::CopyFileRange { .. } | Op::SendFile { .. } | Op::MmapWrite { .. }
    ) && trace.op_results.iter().any(|r| r.ok));

    for r in &trace.regions {
        if r.pre_hash != r.post_hash && !has_writer {
            return Some(Finding {
                kind: FindingKind::ReadOnlyMutation,
                program: prog.clone(),
                description: format!("region {} mutated without writer op", r.region_id),
                evidence: format!("pre={} post={}",
                    hex::encode(r.pre_hash), hex::encode(r.post_hash)),
            });
        }
    }

    // Rule 2: msync divergence — file content should match region post-snapshot
    // after a successful MS_SYNC, if the file was the backing store.
    for f in &trace.files {
        if f.pre_hash != f.post_hash {
            // a file changed — fine if a writer touched it
            if !has_writer {
                return Some(Finding {
                    kind: FindingKind::GhostWrite,
                    program: prog.clone(),
                    description: format!("file {} changed without writer", f.path.display()),
                    evidence: format!("pre={} post={}",
                        hex::encode(f.pre_hash), hex::encode(f.post_hash)),
                });
            }
        }
    }

    // Rule 3: any op reported ok but ret == 0 while len > 0 and it's a copy class op
    for (i, r) in trace.op_results.iter().enumerate() {
        if r.ok && r.ret == 0 {
            if let Some(op) = prog.ops.get(i) {
                let len = match op {
                    Op::Splice { len, .. } | Op::Vmsplice { len, .. }
                    | Op::SendMsg { len, .. } | Op::RecvMsg { len, .. }
                    | Op::CopyFileRange { len, .. } | Op::SendFile { len, .. }
                    | Op::MmapWrite { len, .. } => *len,
                    _ => 0,
                };
                if len > 0 && matches!(op,
                    Op::Splice {..} | Op::Vmsplice {..} | Op::CopyFileRange {..} | Op::SendFile {..})
                {
                    return Some(Finding {
                        kind: FindingKind::SilentNoOp,
                        program: prog.clone(),
                        description: format!("op {} returned 0 but len={}", i, len),
                        evidence: format!("op={:?}", op),
                    });
                }
            }
        }
    }

    None
}
