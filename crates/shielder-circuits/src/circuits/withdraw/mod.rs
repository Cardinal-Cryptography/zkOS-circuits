use strum_macros::{EnumCount, EnumIter};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::WithdrawCircuit;
pub use knowledge::WithdrawProverKnowledge;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum WithdrawInstance {
    Commitment,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum WithdrawFullInstance {
    IdHiding,
    MerkleRoot,
    HashedOldNullifier,
    HashedNewNote,
    WithdrawalValue,
    TokenAddress,
    Commitment,
    MacSalt,
    MacCommitment,
}
