use core::array;

pub use chip::ShortlistHashChip;
use halo2_proofs::plonk::Error;

use crate::{consts::POSEIDON_RATE, embed::Embed, synthesizer::Synthesizer, AssignedCell, Value};

mod chip;
pub mod off_circuit;

const CHUNK_SIZE: usize = POSEIDON_RATE - 1;

/// Represents a (short) list of field elements.
///
/// Hashing is implemented by chaining fixed-sized chunks of the list.
#[derive(Copy, Clone, Debug)]
pub struct Shortlist<T, const N: usize> {
    items: [T; N],
}

impl<const N: usize> Embed for Shortlist<Value, N> {
    type Embedded = Shortlist<AssignedCell, N>;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<alloc::string::String>,
    ) -> Result<Self::Embedded, Error> {
        let items = self.items.embed(synthesizer, annotation)?;
        Ok(Shortlist { items })
    }
}

impl<T, const N: usize> From<[T; N]> for Shortlist<T, N> {
    fn from(items: [T; N]) -> Self {
        Self { items }
    }
}

impl<T: Default, const N: usize> Default for Shortlist<T, N> {
    fn default() -> Self {
        Self {
            items: array::from_fn(|_| T::default()),
        }
    }
}

impl<T, const N: usize> Shortlist<T, N> {
    pub fn new(items: [T; N]) -> Self {
        const { assert!(N > 0 && N % CHUNK_SIZE == 0) };
        Self { items }
    }

    pub fn items(&self) -> &[T; N] {
        &self.items
    }

    pub fn map<R>(self, f: impl Fn(T) -> R) -> Shortlist<R, N> {
        Shortlist {
            items: self.items.map(f),
        }
    }
}
