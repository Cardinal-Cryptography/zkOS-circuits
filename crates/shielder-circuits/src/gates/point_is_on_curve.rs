use alloc::vec;

use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Constraints, ErrorFront, Selector},
    poly::Rotation,
};
use macros::embeddable;

use super::copy_grumpkin_advices;
use crate::{
    column_pool::{AccessColumn, ColumnPool, ConfigPhase},
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell,
};
