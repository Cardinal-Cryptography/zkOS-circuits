use halo2_proofs::arithmetic::Field;

use super::{PointAffine, PointProjective};

pub fn affine_to_projective<F: Field>(p: PointAffine<F>) -> PointProjective<F> {
    PointProjective {
        x: p.x,
        y: p.y,
        z: F::ONE,
    }
}

pub fn projective_to_affine<F: Field>(p: PointProjective<F>) -> PointAffine<F> {
    let z_inverse =
        p.z.invert()
            .expect("no multiplicative inverse to the element");

    PointAffine {
        x: p.x.mul(z_inverse),
        y: p.y.mul(z_inverse),
    }
}
