use strum_macros::{EnumCount, EnumIter};

use crate::{chips::note::NoteInstance, merkle::MerkleInstance};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::WithdrawCircuit;
pub use knowledge::WithdrawProverKnowledge;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum WithdrawInstance {
    IdHiding,
    MerkleRoot,
    HashedOldNullifier,
    HashedNewNote,
    WithdrawalValue,
    TokenAddress,
    Commitment,
}

impl TryFrom<WithdrawInstance> for MerkleInstance {
    type Error = ();

    fn try_from(value: WithdrawInstance) -> Result<Self, Self::Error> {
        match value {
            WithdrawInstance::MerkleRoot => Ok(Self::MerkleRoot),
            _ => Err(()),
        }
    }
}

impl TryFrom<WithdrawInstance> for NoteInstance {
    type Error = ();

    fn try_from(value: WithdrawInstance) -> Result<Self, Self::Error> {
        match value {
            WithdrawInstance::TokenAddress => Ok(NoteInstance::TokenAddress),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use strum::IntoEnumIterator;

    use super::{WithdrawInstance, WithdrawInstance::*};

    #[test]
    fn instance_order() {
        // This is the order used in other parts of the codebase (e.g., in contracts).
        let expected_order = vec![
            IdHiding,
            MerkleRoot,
            HashedOldNullifier,
            HashedNewNote,
            WithdrawalValue,
            TokenAddress,
            Commitment,
        ];
        assert_eq!(expected_order, WithdrawInstance::iter().collect::<Vec<_>>());
    }
}
