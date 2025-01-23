use halo2_proofs::{circuit::Layouter, plonk::Error};
use strum::IntoEnumIterator;
use MerkleInstance::MerkleRoot;

use crate::{
    circuits::merkle::knowledge::MerkleProverKnowledge,
    consts::merkle_constants::ARITY,
    gates::{
        membership::{MembershipGate, MembershipGateInput},
        Gate,
    },
    instance_wrapper::InstanceWrapper,
    merkle::{MerkleConstraints, MerkleConstraints::*, MerkleInstance},
    poseidon::circuit::{hash, PoseidonChip},
    todo::Todo,
    AssignedCell, F,
};

#[derive(Clone, Debug)]
pub struct MerkleChip {
    pub public_inputs: InstanceWrapper<MerkleInstance>,
    pub membership_gate: MembershipGate<ARITY>,
    pub poseidon: PoseidonChip,
}

impl MerkleChip {
    pub fn synthesize<
        const TREE_HEIGHT: usize,
        Constraint: From<MerkleConstraints> + Ord + IntoEnumIterator,
    >(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &MerkleProverKnowledge<TREE_HEIGHT, AssignedCell>,
        todo: &mut Todo<Constraint>,
    ) -> Result<(), Error> {
        let mut current_root = knowledge.leaf.clone();

        for (id, level) in knowledge.path.clone().into_iter().enumerate() {
            // 1. Check if the new level contains the current root.
            self.membership_gate.apply_in_new_region(
                layouter,
                MembershipGateInput {
                    needle: current_root,
                    haystack: level.clone(),
                },
            )?;
            if id == 0 {
                todo.check_off(Constraint::from(MembershipProofContainsSpecificLeaf))?;
            }

            // 2. Compute new root.
            current_root = hash(layouter, self.poseidon.clone(), level)?;
        }
        todo.check_off(Constraint::from(MembershipProofIsCorrect))?;

        self.public_inputs
            .constrain_cells(layouter, [(current_root, MerkleRoot)])?;
        todo.check_off(Constraint::from(MerkleRootInstanceIsConstrainedToAdvice))
    }
}
