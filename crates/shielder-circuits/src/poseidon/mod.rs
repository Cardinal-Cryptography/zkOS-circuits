use halo2_poseidon::poseidon::primitives::ConstantLength;
use spec::PoseidonSpec;

use crate::{
    consts::merkle_constants::{ARITY, WIDTH},
    poseidon::circuit::PoseidonChip,
};

pub mod spec;

pub type PoseidonCircuitHash<F, const LENGTH: usize> = halo2_poseidon::poseidon::Hash<
    F,
    PoseidonChip<F>,
    PoseidonSpec,
    ConstantLength<LENGTH>,
    WIDTH,
    ARITY,
>;

pub type PoseidonOffCircuitHash<F, const LENGTH: usize> =
    halo2_poseidon::poseidon::primitives::Hash<
        F,
        PoseidonSpec,
        ConstantLength<LENGTH>,
        WIDTH,
        ARITY,
    >;

pub mod off_circuit {
    use crate::{poseidon::PoseidonOffCircuitHash, FieldExt};

    /// Compute Poseidon hash of `input` (off-circuit).
    pub fn hash<F: FieldExt, const LENGTH: usize>(input: &[F; LENGTH]) -> F {
        PoseidonOffCircuitHash::<F, LENGTH>::init().hash(*input)
    }
}

pub mod circuit {
    use halo2_proofs::{circuit::Layouter, plonk::Error};

    use crate::{
        consts::merkle_constants::{ARITY, WIDTH},
        poseidon::PoseidonCircuitHash,
        AssignedCell, FieldExt,
    };

    pub type PoseidonConfig<F> = halo2_poseidon::poseidon::Pow5Config<F, WIDTH, ARITY>;
    pub type PoseidonChip<F> = halo2_poseidon::poseidon::Pow5Chip<F, WIDTH, ARITY>;

    /// Compute Poseidon hash of `input` (in-circuit).
    pub fn hash<F: FieldExt, const LENGTH: usize>(
        layouter: &mut impl Layouter<F>,
        poseidon_chip: PoseidonChip<F>,
        input: [AssignedCell<F>; LENGTH],
    ) -> Result<AssignedCell<F>, Error> {
        PoseidonCircuitHash::<F, LENGTH>::init(poseidon_chip, layouter.namespace(|| "Hash init"))?
            .hash(layouter.namespace(|| "Poseidon hash"), input)
    }
}
