use strum_macros::{EnumCount, EnumIter};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::NewAccountCircuit;
pub use knowledge::NewAccountProverKnowledge;

use crate::chips::note::NoteInstance;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum NewAccountInstance {
    HashedNote,
    Prenullifier,
    InitialDeposit,
    TokenAddress,
    AnonymityRevokerPublicKeyX,
    AnonymityRevokerPublicKeyY,
    SymKeyEncryptionCiphertext1X,
    SymKeyEncryptionCiphertext1Y,
    SymKeyEncryptionCiphertext2X,
    SymKeyEncryptionCiphertext2Y,
}

impl TryFrom<NewAccountInstance> for NoteInstance {
    type Error = ();

    fn try_from(value: NewAccountInstance) -> Result<Self, Self::Error> {
        match value {
            NewAccountInstance::TokenAddress => Ok(NoteInstance::TokenAddress),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use strum::IntoEnumIterator;

    use super::{NewAccountInstance, NewAccountInstance::*};

    #[test]
    fn instance_order() {
        // This is the order used in other parts of the codebase (e.g., in contracts).
        let expected_order = vec![
            HashedNote,
            Prenullifier,
            InitialDeposit,
            TokenAddress,
            AnonymityRevokerPublicKeyX,
            AnonymityRevokerPublicKeyY,
            SymKeyEncryptionCiphertext1X,
            SymKeyEncryptionCiphertext1Y,
            SymKeyEncryptionCiphertext2X,
            SymKeyEncryptionCiphertext2Y,
        ];
        assert_eq!(
            expected_order,
            NewAccountInstance::iter().collect::<Vec<_>>()
        );
    }
}
