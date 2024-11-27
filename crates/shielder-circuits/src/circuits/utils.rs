use crate::{consts::merkle_constants::ARITY, FieldExt};

/// No-const-generic version of `crate::circuits::poseidon::off_circuit::hash`.
pub fn hash<F: FieldExt>(input: &[F; ARITY]) -> F {
    crate::poseidon::off_circuit::hash::<F>(input)
}

/// No-const-generic version of `crate::circuits::poseidon::off_circuit::padded_hash`.
pub fn padded_hash<F: FieldExt>(input: &[F]) -> F {
    crate::poseidon::off_circuit::padded_hash::<F>(input)
}
