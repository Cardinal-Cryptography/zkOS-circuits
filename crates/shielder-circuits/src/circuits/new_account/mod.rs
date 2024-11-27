use strum_macros::{EnumCount, EnumIter};

mod chip;
mod circuit;
mod knowledge;

pub use circuit::*;
pub use knowledge::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum NewAccountInstance {
    HashedNote,
    HashedId,
    InitialDeposit,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum NewAccountConstraints {
    /// The public instance is copy-constrained to some cell in advice area.
    HashedNoteInstanceIsConstrainedToAdvice,
    /// The note is correctly computed.
    HashedNoteIsCorrect,

    /// The public instance is copy-constrained to some cell in advice area.
    HashedIdInstanceIsConstrainedToAdvice,
    /// The id is correctly hashed.
    HashedIdIsCorrect,
    /// The id is correctly included in the note.
    IdIsIncludedInTheNote,

    /// The public instance is copy-constrained to some cell in advice area.
    InitialDepositInstanceIsConstrainedToAdvice,
    /// The initial deposit is correctly included in the note.
    InitialDepositIsIncludedInTheNewNote,
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use strum::IntoEnumIterator;

    use super::{NewAccountInstance, NewAccountInstance::*};

    #[test]
    fn instance_order() {
        // This is the order used in other parts of the codebase (e.g., in contracts).
        let expected_order = vec![HashedNote, HashedId, InitialDeposit];
        assert_eq!(
            expected_order,
            NewAccountInstance::iter().collect::<Vec<_>>()
        );
    }
}
