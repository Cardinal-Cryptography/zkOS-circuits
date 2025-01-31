pub mod off_circuit {
    use crate::Fr;

    pub fn encrypt(_key: Fr, _message: Fr) -> Fr {
        // TODO: Implement encryption
        Fr::zero()
    }
}

#[derive(Clone, Debug)]
pub struct ElGamalEncryptionChip;

impl ElGamalEncryptionChip {
    pub fn encrypt() {}
}
