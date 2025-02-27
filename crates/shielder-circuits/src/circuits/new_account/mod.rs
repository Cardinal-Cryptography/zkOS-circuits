use strum_macros::{EnumCount, EnumIter};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::NewAccountCircuit;
pub use knowledge::NewAccountProverKnowledge;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum NewAccountInstance {
    Commitment,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum NewAccountFullInstance {
    HashedNote,
    HashedId,
    InitialDeposit,
    TokenAddress,
    AnonymityRevokerPublicKeyX,
    AnonymityRevokerPublicKeyY,
    SymKeyEncryptionCiphertext1X,
    SymKeyEncryptionCiphertext1Y,
    SymKeyEncryptionCiphertext2X,
    SymKeyEncryptionCiphertext2Y,
}
