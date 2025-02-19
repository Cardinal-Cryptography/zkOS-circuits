use core::ops::{Add, Mul, Sub};

use halo2_frontend::plonk::Expression;
use halo2_proofs::{arithmetic::CurveExt, halo2curves::grumpkin::G1};

use crate::{Field, Fr, Value};

/// An abstraction over the scalar field of the curve.
pub trait CurveScalarField:
    Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + Clone
{
    /// Returns the parameter `b` from the curve equation.
    fn b() -> Self;
    /// Returns the parameter `b` from the curve equation added to itself 3 times.
    fn b3() -> Self;
    /// Returns the zero element of the scalar field.
    fn zero() -> Self;
    /// Returns the one element of the scalar field.
    fn one() -> Self;
    // /// Returns the square root of the field element, if it is quadratic residue and None if it is not
    // fn square_root(&self) -> Option<Self>;
}

impl CurveScalarField for Fr {
    fn b() -> Self {
        G1::b()
    }
    fn b3() -> Self {
        Self::b() + Self::b() + Self::b()
    }

    fn zero() -> Self {
        Fr::ZERO
    }

    fn one() -> Self {
        Fr::ONE
    }

    // fn square_root(&self) -> Option<Self> {
    //     Fr::sqrt(self).into_option()
    // }
}

impl CurveScalarField for Value {
    fn b() -> Self {
        Value::known(G1::b())
    }
    fn b3() -> Self {
        Value::known(Fr::b3())
    }

    fn zero() -> Self {
        Value::known(Fr::zero())
    }

    fn one() -> Self {
        Value::known(Fr::one())
    }

    // fn square_root(&self) -> Option<Self> {
    //     let mut square_root = None;
    //     self.map(|element| {
    //         square_root = element.sqrt().into_option();
    //     });
    //     square_root
    // }
}

impl CurveScalarField for Expression<Fr> {
    fn b() -> Self {
        Expression::Constant(Fr::b())
    }
    fn b3() -> Self {
        Expression::Constant(Fr::b3())
    }

    fn zero() -> Self {
        Expression::Constant(Fr::zero())
    }

    fn one() -> Self {
        Expression::Constant(Fr::one())
    }

    // fn square_root(&self) -> Option<Self> {

    // }
}
