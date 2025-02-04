use strum_macros::{EnumCount, EnumIter};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::NewAccountCircuit;
pub use knowledge::NewAccountProverKnowledge;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum NewAccountInstance {
    HashedNote,
    HashedId,
    InitialDeposit,
    AnonymityRevokerPublicKey,
    SymKeyEncryption,
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
            HashedId,
            InitialDeposit,
            AnonymityRevokerPublicKey,
            SymKeyEncryption,
        ];
        assert_eq!(
            expected_order,
            NewAccountInstance::iter().collect::<Vec<_>>()
        );
    }
}
