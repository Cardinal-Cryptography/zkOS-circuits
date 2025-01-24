use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::Gate,
    synthesizer::Synthesizer,
    AssignedCell,
};
