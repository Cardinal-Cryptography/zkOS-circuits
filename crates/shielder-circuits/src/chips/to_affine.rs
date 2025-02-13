use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct ToAffineChipInput<T> {
    pub point_projective: GrumpkinPoint<T>,
    pub point_projective_z_inverse: T,
}
