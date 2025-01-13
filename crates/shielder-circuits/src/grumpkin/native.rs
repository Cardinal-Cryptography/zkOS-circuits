use halo2_proofs::{arithmetic::Field, halo2curves::grumpkin::G1};

use crate::FieldExt;

#[derive(Clone, Copy, Debug)]
pub struct PointAffine<F: Field> {
    pub x: F,
    pub y: F,
}

// TODO: gen

#[cfg(test)]
mod test {

    #[test]
    fn test_group_generator() {
        todo!()
    }
}
