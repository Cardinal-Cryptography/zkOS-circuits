use halo2_poseidon::poseidon::primitives::ConstantLength;
use spec::PoseidonSpec;

use crate::{
    consts::merkle_constants::{ARITY, WIDTH},
    poseidon::circuit::PoseidonChip,
    Fr,
};

pub mod spec;

pub type PoseidonCircuitHash<const LENGTH: usize> = halo2_poseidon::poseidon::Hash<
    Fr,
    PoseidonChip,
    PoseidonSpec,
    ConstantLength<LENGTH>,
    WIDTH,
    ARITY,
>;

pub type PoseidonOffCircuitHash<const LENGTH: usize> = halo2_poseidon::poseidon::primitives::Hash<
    Fr,
    PoseidonSpec,
    ConstantLength<LENGTH>,
    WIDTH,
    ARITY,
>;

pub mod off_circuit {
    use crate::{poseidon::PoseidonOffCircuitHash, Fr};

    /// Compute Poseidon hash of `input` (off-circuit).
    pub fn hash<const LENGTH: usize>(input: &[Fr; LENGTH]) -> Fr {
        PoseidonOffCircuitHash::<LENGTH>::init().hash(*input)
    }
}

pub mod circuit {
    use halo2_proofs::{circuit::Layouter, plonk::Error};

    use crate::{
        consts::merkle_constants::{ARITY, WIDTH},
        poseidon::PoseidonCircuitHash,
        AssignedCell, Fr,
    };

    pub type PoseidonConfig = halo2_poseidon::poseidon::Pow5Config<Fr, WIDTH, ARITY>;
    pub type PoseidonChip = halo2_poseidon::poseidon::Pow5Chip<Fr, WIDTH, ARITY>;

    /// Compute Poseidon hash of `input` (in-circuit).
    pub fn hash<const LENGTH: usize>(
        layouter: &mut impl Layouter<Fr>,
        poseidon_chip: PoseidonChip,
        input: [AssignedCell; LENGTH],
    ) -> Result<AssignedCell, Error> {
        PoseidonCircuitHash::<LENGTH>::init(poseidon_chip, layouter.namespace(|| "Hash init"))?
            .hash(layouter.namespace(|| "Poseidon hash"), input)
    }
}
