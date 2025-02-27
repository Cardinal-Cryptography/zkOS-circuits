use halo2_proofs::plonk::Error;

use crate::{
    circuits::merkle::knowledge::MerkleProverKnowledge,
    consts::merkle_constants::ARITY,
    gates::{
        membership::{MembershipGate, MembershipGateInput},
        Gate,
    },
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct MerkleChip {
    pub membership_gate: MembershipGate<ARITY>,
    pub poseidon: PoseidonChip,
}

impl MerkleChip {
    pub fn synthesize<const TREE_HEIGHT: usize>(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &MerkleProverKnowledge<TREE_HEIGHT, AssignedCell>,
    ) -> Result<AssignedCell, Error> {
        let mut current_root = knowledge.leaf.clone();

        for level in knowledge.path.clone().into_iter() {
            // 1. Check if the new level contains the current root.
            self.membership_gate.apply_in_new_region(
                synthesizer,
                MembershipGateInput {
                    needle: current_root,
                    haystack: level.clone(),
                },
            )?;

            // 2. Compute new root.
            current_root = hash(synthesizer, self.poseidon.clone(), level)?;
        }
        Ok(current_root)
    }
}
