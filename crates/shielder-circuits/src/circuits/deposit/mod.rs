use strum_macros::{EnumCount, EnumIter};

use crate::{chips::note::NoteInstance, merkle::MerkleInstance};

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
    TokenAddress,
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

impl TryFrom<DepositInstance> for NoteInstance {
    type Error = ();

    fn try_from(value: DepositInstance) -> Result<Self, Self::Error> {
        match value {
            DepositInstance::TokenAddress => Ok(NoteInstance::TokenAddress),
            _ => Err(()),
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
            TokenAddress,
        ];
        assert_eq!(expected_order, DepositInstance::iter().collect::<Vec<_>>());
    }
}
