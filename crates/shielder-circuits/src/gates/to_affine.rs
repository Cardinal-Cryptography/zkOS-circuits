use alloc::vec;

use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use macros::embeddable;

use crate::{
    column_pool::{AccessColumn, ConfigPhase},
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell, Fr,
};
