use strum_macros::{EnumCount, EnumIter};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::DepositCircuit;
pub use knowledge::DepositProverKnowledge;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum DepositInstance {
    Commitment,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum DepositFullInstance {
    IdHiding,
    MerkleRoot,
    HashedOldNullifier,
    HashedNewNote,
    DepositValue,
    TokenAddress,
    MacSalt,
    MacCommitment,
}
