//! Canonical access trees and exact signing sets (DESIGN §2.4).
use super::group::{lagrange, Secp, Suite};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LeafId {
    /// Canonical charter labels, not Shamir evaluation coordinates. Threshold
    /// coordinates are the one-based positions of children in their gate.
    pub slot: u16,
    pub path: Vec<u16>,
    pub member: u16,
}
impl LeafId {
    pub fn new(slot: u16, path: Vec<u16>, member: u16) -> Self {
        Self { slot, path, member }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.slot.to_be_bytes().to_vec();
        out.extend_from_slice(&(self.path.len() as u64).to_be_bytes());
        for index in &self.path {
            out.extend_from_slice(&index.to_be_bytes());
        }
        out.extend_from_slice(&self.member.to_be_bytes());
        out
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Gate {
    Leaf(LeafId),
    And(Vec<Gate>),
    Threshold { k: usize, children: Vec<Gate> },
    Or(Vec<Gate>),
}
impl Gate {
    pub fn validate(&self) -> Result<()> {
        self.leaves().map(|_| ())
    }
    pub fn leaves(&self) -> Result<Vec<LeafId>> {
        fn visit(g: &Gate, leaves: &mut BTreeSet<LeafId>, depth: usize) -> Result<()> {
            if depth > 64 {
                return Err(Error::Parameters);
            }
            let children = match g {
                Gate::Leaf(id) => {
                    if id.path.len() > 64 || !leaves.insert(id.clone()) {
                        return Err(Error::Parameters);
                    }
                    return Ok(());
                }
                Gate::And(c) | Gate::Or(c) => c,
                Gate::Threshold { k, children } => {
                    if *k == 0 || *k > children.len() {
                        return Err(Error::Threshold);
                    }
                    children
                }
            };
            if children.is_empty() || children.len() > u16::MAX as usize {
                return Err(Error::Parameters);
            }
            for c in children {
                visit(c, leaves, depth + 1)?;
            }
            Ok(())
        }
        let mut leaves = BTreeSet::new();
        visit(self, &mut leaves, 0)?;
        Ok(leaves.into_iter().collect())
    }
    pub fn weights<S: Suite>(&self, signers: &[LeafId]) -> Result<BTreeMap<LeafId, S::Scalar>> {
        let all: BTreeSet<_> = self.leaves()?.into_iter().collect();
        let selected: BTreeSet<_> = signers.iter().cloned().collect();
        if selected.len() != signers.len() || !selected.is_subset(&all) || selected.is_empty() {
            return Err(Error::Threshold);
        }
        fn walk<S: Suite>(
            g: &Gate,
            set: &BTreeSet<LeafId>,
        ) -> Result<Option<BTreeMap<LeafId, S::Scalar>>> {
            match g {
                Gate::Leaf(id) => Ok(set
                    .contains(id)
                    .then(|| BTreeMap::from([(id.clone(), S::scalar_one())]))),
                Gate::And(children) | Gate::Or(children) | Gate::Threshold { children, .. } => {
                    let mut active = Vec::new();
                    for (i, c) in children.iter().enumerate() {
                        if let Some(w) = walk::<S>(c, set)? {
                            active.push(((i + 1) as u16, w));
                        }
                    }
                    if active.is_empty() {
                        return Ok(None);
                    }
                    let expected = match g {
                        Gate::And(_) => children.len(),
                        Gate::Or(_) => 1,
                        Gate::Threshold { k, .. } => *k,
                        _ => unreachable!(),
                    };
                    if active.len() != expected {
                        return Err(Error::Threshold);
                    }
                    let indices: Vec<_> = active.iter().map(|(i, _)| *i).collect();
                    let factors = if matches!(g, Gate::Threshold { .. }) {
                        lagrange::<S>(&indices)?
                    } else {
                        vec![S::scalar_one(); active.len()]
                    };
                    let mut weights = BTreeMap::new();
                    for ((_, branch), factor) in active.into_iter().zip(factors) {
                        for (id, w) in branch {
                            weights.insert(id, w * factor);
                        }
                    }
                    Ok(Some(weights))
                }
            }
        }
        walk::<S>(self, &selected)?.ok_or(Error::Threshold)
    }
    pub fn satisfies(&self, signers: &[LeafId]) -> bool {
        self.weights::<Secp>(signers).is_ok()
    }
    pub fn check_initiator(
        &self,
        signers: &[LeafId],
        initiator: &LeafId,
        allowed: &[LeafId],
    ) -> Result<()> {
        if !signers.contains(initiator) || !allowed.contains(initiator) {
            return Err(Error::Context);
        }
        self.weights::<Secp>(signers).map(|_| ())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        fn write(g: &Gate, out: &mut Vec<u8>) {
            let children = match g {
                Gate::Leaf(id) => {
                    out.push(0);
                    out.extend_from_slice(&id.encode());
                    return;
                }
                Gate::And(c) => {
                    out.push(1);
                    c
                }
                Gate::Threshold { k, children } => {
                    out.push(2);
                    out.extend_from_slice(&(*k as u16).to_be_bytes());
                    children
                }
                Gate::Or(c) => {
                    out.push(3);
                    c
                }
            };
            out.extend_from_slice(&(children.len() as u16).to_be_bytes());
            for c in children {
                write(c, out);
            }
        }
        let mut out = Vec::new();
        write(self, &mut out);
        Ok(out)
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(crate::hash::h("SL1/access", &self.encode()?))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn leaf(i: u16) -> Gate {
        Gate::Leaf(LeafId::new(0, vec![], i))
    }
    #[test]
    fn exact_subsets_and_initiators() {
        let g = Gate::Threshold {
            k: 2,
            children: vec![leaf(1), leaf(2), leaf(3)],
        };
        let ids = g.leaves().unwrap();
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let set = vec![ids[pair[0]].clone(), ids[pair[1]].clone()];
            assert!(g.satisfies(&set));
            assert!(g.check_initiator(&set, &set[0], &set).is_ok());
        }
        assert!(!g.satisfies(&ids));
        assert!(!g.satisfies(&ids[..1]));
        assert!(g.check_initiator(&ids[..2], &ids[2], &ids).is_err());
    }
    #[test]
    fn rejects_extra_unknown_duplicate_and_partial_branch() {
        let g = Gate::Or(vec![leaf(1), Gate::And(vec![leaf(2), leaf(3)])]);
        let ids = g.leaves().unwrap();
        assert!(g.satisfies(&ids[..1]));
        assert!(g.satisfies(&ids[1..]));
        assert!(!g.satisfies(&ids));
        assert!(!g.satisfies(&ids[1..2]));
        assert!(!g.satisfies(&[ids[0].clone(), ids[0].clone()]));
        assert!(!g.satisfies(&[LeafId::new(9, vec![], 1)]));
        assert!(Gate::And(vec![leaf(1), leaf(1)]).hash().is_err());
    }
    #[test]
    fn canonical_encoding_binds_paths_order_and_gate() {
        let a = Gate::And(vec![leaf(1), leaf(2)]);
        let b = Gate::And(vec![leaf(2), leaf(1)]);
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
        assert_ne!(
            a.hash().unwrap(),
            Gate::Or(vec![leaf(1), leaf(2)]).hash().unwrap()
        );
        assert_ne!(
            LeafId::new(1, vec![2], 3).encode(),
            LeafId::new(1, vec![], 2).encode()
        );
    }
}
