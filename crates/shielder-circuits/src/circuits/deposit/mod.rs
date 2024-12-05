use strum_macros::{EnumCount, EnumIter};

use crate::merkle::{MerkleConstraints, MerkleInstance};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::DepositCircuit;
pub use knowledge::DepositProverKnowledge;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum DepositInstance {
    IdHiding,
    MerkleRoot,
    HashedOldNullifier,
    HashedNewNote,
    DepositValue,
}

impl TryFrom<DepositInstance> for MerkleInstance {
    type Error = ();

    fn try_from(value: DepositInstance) -> Result<Self, Self::Error> {
        match value {
            DepositInstance::MerkleRoot => Ok(MerkleInstance::MerkleRoot),
            _ => Err(()),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum DepositConstraints {
    /// Merkle path should be a correct membership proof.
    MembershipProofIsCorrect,
    /// The old note belongs to the first level of the Merkle path.
    MembershipProofRelatesToTheOldNote,
    /// The public instance is a commitment to the Merkle path.
    MerkleRootInstanceIsConstrainedToAdvice,

    /// The public instance is copy-constrained to some cell in advice area.
    HashedOldNullifierInstanceIsConstrainedToAdvice,
    /// The old nullifier is correctly hashed.
    HashedOldNullifierIsCorrect,
    /// The old nullifier is correctly included in the old note.
    OldNullifierIsIncludedInTheOldNote,

    /// The public instance is copy-constrained to some cell in advice area.
    DepositValueInstanceIsConstrainedToAdvice,
    /// The deposit value is correctly included in the new note.
    DepositValueInstanceIsIncludedInTheNewNote,

    /// The public instance is copy-constrained to some cell in advice area.
    HashedNewNoteInstanceIsConstrainedToAdvice,
    /// The new note is correctly hashed.
    HashedNewNoteIsCorrect,

    /// IdHiding is correctly calculated from a `nonce` and `id` advice cells
    IdHidingIsCorrect,
    /// The public instance is copy-constrained to some cell in advice area.
    IdHidingInstanceIsConstrainedToAdvice,
}

impl From<MerkleConstraints> for DepositConstraints {
    fn from(merkle: MerkleConstraints) -> Self {
        use MerkleConstraints::*;
        match merkle {
            MembershipProofIsCorrect => Self::MembershipProofIsCorrect,
            MembershipProofContainsSpecificLeaf => Self::MembershipProofRelatesToTheOldNote,
            MerkleRootInstanceIsConstrainedToAdvice => {
                Self::MerkleRootInstanceIsConstrainedToAdvice
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use strum::IntoEnumIterator;

    use super::{DepositInstance, DepositInstance::*};

    #[test]
    fn instance_order() {
        // This is the order used in other parts of the codebase (e.g., in contracts).
        let expected_order = vec![
            IdHiding,
            MerkleRoot,
            HashedOldNullifier,
            HashedNewNote,
            DepositValue,
        ];
        assert_eq!(expected_order, DepositInstance::iter().collect::<Vec<_>>());
    }
}
