pub use crate::poseidon::off_circuit::hash;
use crate::{consts::POSEIDON_RATE, FieldExt};

const RANGE_BOUND: usize = POSEIDON_RATE + 1;

/// Hashes a variable-length input using const-length Poseidon
pub fn hash_variable_length<F: FieldExt>(input: &[F]) -> F {
    match input.len() {
        1 => hash::<F, 1>(input.try_into().expect("Safe to unwrap - checked length")),
        2 => hash::<F, 2>(input.try_into().expect("Safe to unwrap - checked length")),
        3 => hash::<F, 3>(input.try_into().expect("Safe to unwrap - checked length")),
        4 => hash::<F, 4>(input.try_into().expect("Safe to unwrap - checked length")),
        5 => hash::<F, 5>(input.try_into().expect("Safe to unwrap - checked length")),
        6 => hash::<F, 6>(input.try_into().expect("Safe to unwrap - checked length")),
        7 => hash::<F, 7>(input.try_into().expect("Safe to unwrap - checked length")),
        0 | RANGE_BOUND.. => panic!(
            "Invalid input length to hash function, expected len between 1 and {}",
            POSEIDON_RATE
        ),
    }
}
