use crate::config::Config;
use crate::executor;
use crate::generator::{Op, Program};
use crate::oracle::{self, Finding};
use crate::report;

/// Greedy delta-debugging: drop ops while the finding persists.
pub fn minimize(cfg: &Config, mut prog: Program, finding: Finding) -> Finding {
    let mut changed = true;
    while changed {
        changed = false;
        let mut i = 0;
        while i < prog.ops.len() {
            let mut trial = prog.clone();
            trial.ops.remove(i);
            if reproduces(cfg, &trial, &finding) {
                prog = trial;
                changed = true;
            } else {
                i += 1;
            }
        }
        // also try shrinking endpoints
        let mut j = 0;
        while j < prog.endpoints.len() {
            let mut trial = prog.clone();
            trial.endpoints.remove(j);
            // reindex ops that referenced removed idx: bail if any refers >= j
            let ok = trial.ops.iter().all(|op| !refers_to(op, j));
            if ok && reproduces(cfg, &trial, &finding) {
                // shift indices
                for op in trial.ops.iter_mut() { shift_indices(op, j); }
                prog = trial;
                changed = true;
            } else {
                j += 1;
            }
        }
    }

    Finding {
        kind: finding.kind,
        program: prog,
        description: finding.description,
        evidence: finding.evidence,
    }
}

fn reproduces(cfg: &Config, prog: &Program, finding: &Finding) -> bool {
    match executor::run(cfg, prog) {
        Ok(trace) => {
            if let Some(f) = oracle::check(cfg, prog, &trace) {
                std::mem::discriminant(&f.kind) == std::mem::discriminant(&finding.kind)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn refers_to(op: &Op, idx: usize) -> bool {
    match op {
        Op::Splice { from, to, .. } => *from == idx || *to == idx,
        Op::Vmsplice { to, .. } => *to == idx,
        Op::SendMsg { to, .. } => *to == idx,
        Op::RecvMsg { from, .. } => *from == idx,
        Op::CopyFileRange { src, dst, .. } => *src == idx || *dst == idx,
        Op::SendFile { out, inp, .. } => *out == idx || *inp == idx,
        Op::Fsync { fd, .. } => *fd == idx,
        _ => false,
    }
}

fn shift_indices(op: &mut Op, removed:
