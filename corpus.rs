use crate::config::Config;
use crate::generator::Program;
use anyhow::Result;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

pub struct Corpus {
    seen: HashSet<u64>,
    programs: Vec<Program>,
}

impl Corpus {
    pub fn new(_cfg: &Config) -> Result<Self> {
        Ok(Self { seen: HashSet::new(), programs: Vec::new() })
    }

    pub fn add(&mut self, p: Program) {
        let h = hash_program(&p);
        if self.seen.insert(h) {
            self.programs.push(p);
        }
    }

    pub fn len(&self) -> usize { self.programs.len() }
}

fn hash_program(p: &Program) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut h = DefaultHasher::new();
    format!("{:?}", p).hash(&mut h);
    h.finish()
}
