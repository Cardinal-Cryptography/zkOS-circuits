use rand_core::RngCore;
use strum_macros::{EnumCount, EnumIter};

use crate::{circuits::FieldExt, consts::merkle_constants::ARITY, poseidon::off_circuit::hash};

mod chip;
mod circuit;
mod knowledge;

pub use chip::MerkleChip;
pub use circuit::MerkleCircuit;
pub use knowledge::MerkleProverKnowledge;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum MerkleInstance {
    MerkleRoot,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum MerkleConstraints {
    /// Merkle path is a correct membership proof.
    MembershipProofIsCorrect,
    /// A specific leaf belongs to the first level of the Merkle path.
    MembershipProofContainsSpecificLeaf,
    /// The public instance is a commitment to the Merkle path.
    MerkleRootInstanceIsConstrainedToAdvice,
}

pub fn generate_example_path_with_given_leaf<F: FieldExt, const TREE_HEIGHT: usize>(
    leaf: F,
    rng: &mut impl RngCore,
) -> (F, [[F; ARITY]; TREE_HEIGHT]) {
    let mut path: [[F; ARITY]; TREE_HEIGHT] =
        [(); TREE_HEIGHT].map(|_| [(); ARITY].map(|_| F::random(&mut *rng)));
    path[0][0] = leaf;

    for i in 1..TREE_HEIGHT {
        path[i][(rng.next_u32() % (ARITY as u32)) as usize] = hash(&path[i - 1]);
    }

    let root = hash(&path[TREE_HEIGHT - 1]);

    (root, path)
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use strum::IntoEnumIterator;

    use super::{MerkleInstance, MerkleInstance::*};

    #[test]
    fn instance_order() {
        // This is the order used in other parts of the codebase (e.g., in contracts).
        let expected_order = vec![MerkleRoot];
        assert_eq!(expected_order, MerkleInstance::iter().collect::<Vec<_>>());
    }
}
