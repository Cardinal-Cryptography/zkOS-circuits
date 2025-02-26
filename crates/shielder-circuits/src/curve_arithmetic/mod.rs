use alloc::vec::Vec;
use core::ops::Mul;

pub use curve_scalar_field::CurveScalarField;
pub use grumpkin_point::{GrumpkinPoint, GrumpkinPointAffine};
use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    halo2curves::{bn256::Fr, ff::PrimeField, grumpkin::G1},
};

use crate::{chips::sym_key, consts::FIELD_BITS};

mod curve_scalar_field;
pub mod grumpkin_point;

/// Algorithm 7 https://eprint.iacr.org/2015/1060.pdf
pub fn points_add<S: CurveScalarField>(
    p: GrumpkinPoint<S>,
    q: GrumpkinPoint<S>,
) -> GrumpkinPoint<S> {
    let GrumpkinPoint {
        x: x1,
        y: y1,
        z: z1,
    } = p;

    let GrumpkinPoint {
        x: x2,
        y: y2,
        z: z2,
    } = q;

    let t0 = x1.clone() * x2.clone();
    let t1 = y1.clone() * y2.clone();
    let t2 = z1.clone() * z2.clone();
    let t3 = x1.clone() + y1.clone();
    let t4 = x2.clone() + y2.clone();
    let t3 = t3 * t4;
    let t4 = t0.clone() + t1.clone();
    let t3 = t3 - t4;
    let t4 = y1 + z1.clone();
    let x3 = y2 + z2.clone();
    let t4 = t4 * x3;
    let x3 = t1.clone() + t2.clone();
    let t4 = t4 - x3;
    let x3 = x1 + z1;
    let y3 = x2 + z2;
    let x3 = x3 * y3;
    let y3 = t0.clone() + t2.clone();
    let y3 = x3 - y3;
    let x3 = t0.clone() + t0.clone();
    let t0 = x3 + t0;
    let t2 = t2 * S::b3();
    let z3 = t1.clone() + t2.clone();
    let t1 = t1 - t2;
    let y3 = y3 * S::b3();
    let x3 = t4.clone() * y3.clone();
    let t2 = t3.clone() * t1.clone();
    let x3 = t2 - x3;
    let y3 = y3 * t0.clone();
    let t1 = t1 * z3.clone();
    let y3 = t1 + y3;
    let t0 = t0 * t3;
    let z3 = z3 * t4;
    let z3 = z3 + t0;

    GrumpkinPoint::new(x3, y3, z3)
}

/// Algorithm 9, https://eprint.iacr.org/2015/1060.pdf
pub fn point_double<S: CurveScalarField>(p: GrumpkinPoint<S>) -> GrumpkinPoint<S> {
    let GrumpkinPoint { x, y, z } = p;

    let t0 = y.clone() * y.clone();
    let z3 = t0.clone() + t0.clone();
    let z3 = z3.clone() + z3;
    let z3 = z3.clone() + z3;
    let t1 = y.clone() * z.clone();
    let t2 = z.clone() * z;
    let t2 = t2 * S::b3();
    let x3 = t2.clone() * z3.clone();
    let y3 = t0.clone() + t2.clone();
    let z3 = t1 * z3;
    let t1 = t2.clone() + t2.clone();
    let t2 = t1 + t2;
    let t0 = t0 - t2;
    let y3 = t0.clone() * y3;
    let y3 = x3 + y3;
    let t1 = x * y;
    let x3 = t0 * t1;
    let x3 = x3.clone() + x3;

    GrumpkinPoint::new(x3, y3, z3)
}

pub fn normalize_point<T: Field>(p: GrumpkinPoint<T>) -> GrumpkinPoint<T> {
    let GrumpkinPoint { x, y, z } = p;
    let z_inv = z.invert().unwrap();
    GrumpkinPoint::new(x * z_inv, y * z_inv, T::ONE)
}

pub fn scalar_multiply<S: CurveScalarField + PartialEq>(
    input: GrumpkinPoint<S>,
    scalar_bits: [S; 127],
) -> GrumpkinPoint<S> {
    let mut result = GrumpkinPoint::zero();

    let mut doubled = input.clone();

    for bit in scalar_bits {
        if bit == S::one() {
            result = points_add(result, doubled.clone());
        }
        doubled = point_double(doubled);
    }
    result
}

pub fn projective_to_affine<T>(p: GrumpkinPoint<T>, z_inverse: T) -> GrumpkinPointAffine<T>
where
    T: Mul<Output = T> + Clone,
{
    GrumpkinPointAffine::new(p.x * z_inverse.clone(), p.y * z_inverse)
}

pub fn affine_to_projective<T: Field>(p: GrumpkinPointAffine<T>) -> GrumpkinPoint<T> {
    GrumpkinPoint::new(p.x, p.y, T::ONE)
}

pub fn is_point_on_curve_affine<S: CurveScalarField + PartialEq>(
    GrumpkinPointAffine { x, y }: GrumpkinPointAffine<S>,
) -> bool {
    y.clone() * y == x.clone() * x.clone() * x + S::b()
}

/// returns y^2 given x on the grumpkin curve
pub fn quadratic_residue_given_x_affine<S: CurveScalarField>(x: S) -> S {
    x.clone() * x.clone() * x + S::b()
}

/// Given a 32 byte array with a field element generates a random `id` such
/// that it's hash, along with a specific salt is the x-coordinate of a point on the (affine) Grumpkin curve:
/// For x = hash(id, SALT), y = sqrt(x^3 + b) P(x,y) \in E
///
/// The procedure is deterministic given the byte array, which is treated as an x-coordinate to start the incremental search with.
pub fn generate_user_id(start_from: [u8; 32]) -> Fr {
    let mut id = Fr::from_bytes(&start_from).expect("not a 32 byte array");

    loop {
        let x = sym_key::off_circuit::derive(id);
        let y_squared = x * x * x + G1::b();
        match y_squared.sqrt().into_option() {
            Some(_) => return id,
            None => {
                id += Fr::one();
            }
        }
    }
}

/// Converts given field element to the individual LE bit representation
///
/// panics if value is not `FIELD_BITS` bits
pub fn field_element_to_le_bits(value: Fr) -> [Fr; FIELD_BITS] {
    let bits_vec = to_bits_le(value.to_repr().as_ref())
        .to_vec()
        .iter()
        .take(FIELD_BITS)
        .map(|&x| Fr::from(u64::from(x)))
        .collect::<Vec<Fr>>();
    bits_vec
        .try_into()
        .unwrap_or_else(|_| panic!("value is not {FIELD_BITS} bits long!"))
}

fn to_bits_le(num: &[u8]) -> Vec<bool> {
    let len = num.len() * 8;
    let mut bits = Vec::new();
    for i in 0..len {
        let bit = num[i / 8] & (1 << (i % 8)) != 0;
        bits.push(bit);
    }
    bits
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        arithmetic::CurveExt,
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
    };

    use super::{field_element_to_le_bits, GrumpkinPointAffine};
    use crate::{
        chips::sym_key,
        curve_arithmetic::{
            self, grumpkin_point::GrumpkinPoint, normalize_point, point_double, points_add,
            scalar_multiply,
        },
        rng, Field,
    };

    #[test]
    fn scalar_multiply_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let n = Fr::from_u128(3);
        let bits = field_element_to_le_bits(n);

        let expected: GrumpkinPoint<Fr> = (p + p + p).into();
        let expected: GrumpkinPoint<Fr> = normalize_point(expected);

        let result = scalar_multiply(p.into(), bits);
        let result = normalize_point(result);

        assert_eq!(expected, result);
    }

    #[test]
    fn adding_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let expected: GrumpkinPoint<Fr> = (p + q).into();

        assert_eq!(expected, points_add(p.into(), q.into()));
    }

    #[test]
    fn doubling_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let expected: GrumpkinPoint<Fr> = (p + p).into();

        assert_eq!(expected, point_double(p.into()));
    }

    #[test]
    fn coordinate_conversion() {
        let rng = rng();

        let p: GrumpkinPoint<Fr> = G1::random(rng).into();
        let p_affine: GrumpkinPointAffine<Fr> = p.into();

        assert_eq!(p, p_affine.into());
        assert_eq!(
            p_affine,
            curve_arithmetic::projective_to_affine(
                p,
                p.z.invert().expect("z coord has an inverse")
            )
        );
        let p_recovered: GrumpkinPoint<Fr> = p_affine.into();

        assert_eq!(p_recovered, p);
        assert_eq!(
            p_recovered,
            curve_arithmetic::affine_to_projective(p_affine)
        );
    }

    #[test]
    fn is_random_point_on_curve_affine() {
        let mut rng = rng();
        let point: GrumpkinPointAffine<Fr> = GrumpkinPointAffine::random(&mut rng);
        assert!(curve_arithmetic::is_point_on_curve_affine(point));
    }

    #[test]
    fn user_id_generation() {
        let bytes = [21u128.to_le_bytes(), 37u128.to_le_bytes()]
            .concat()
            .try_into()
            .expect("not a 32 byte array");

        let id = curve_arithmetic::generate_user_id(bytes);
        let x = sym_key::off_circuit::derive(id);
        let y = (x * x * x + G1::b())
            .sqrt()
            .expect("element is not a quadratic residue");
        let point = GrumpkinPointAffine::new(x, y);

        assert!(curve_arithmetic::is_point_on_curve_affine(point));
    }
}
