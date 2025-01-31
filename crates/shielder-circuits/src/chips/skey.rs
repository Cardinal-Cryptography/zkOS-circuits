use crate::poseidon::circuit::PoseidonChip;

pub mod off_circuit {
    use halo2_proofs::halo2curves::ff::PrimeField;

    use crate::{consts::SKEY_SALT, poseidon::off_circuit::hash, Fr};

    pub fn derive(id: Fr) -> Fr {
        hash(&[id, Fr::from_u128(SKEY_SALT)])
    }
}

#[derive(Clone, Debug)]
pub struct SKeyChip {
    poseidon: PoseidonChip,
}
