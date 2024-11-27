use halo2_poseidon::poseidon::primitives::ConstantLength;
use spec::PoseidonSpec;

use crate::{
    consts::merkle_constants::{ARITY, WIDTH},
    poseidon::circuit::PoseidonChip,
};

pub mod spec;

pub type PoseidonCircuitHash<F> = halo2_poseidon::poseidon::Hash<
    F,
    PoseidonChip<F>,
    PoseidonSpec,
    ConstantLength<ARITY>,
    WIDTH,
    ARITY,
>;
pub type PoseidonOffCircuitHash<F> = halo2_poseidon::poseidon::primitives::Hash<
    F,
    PoseidonSpec,
    ConstantLength<ARITY>,
    WIDTH,
    ARITY,
>;

fn pad<const TARGET_LEN: usize, Element: Clone>(
    array: &[Element],
    padding: Element,
) -> [Element; TARGET_LEN] {
    assert!(array.len() <= TARGET_LEN, "Array is too long");
    // needed because `Element` is not necessarily `Copy`, which is req for `[padding; TARGET_LEN]`
    let mut padded = core::array::from_fn(|_| padding.clone());
    padded[..array.len()].clone_from_slice(array);
    padded
}

pub mod off_circuit {
    use crate::{
        consts::merkle_constants::ARITY,
        poseidon::{pad, PoseidonOffCircuitHash},
        FieldExt,
    };

    /// Compute Poseidon hash of `input` (off-circuit).
    pub fn hash<F: FieldExt>(input: &[F; ARITY]) -> F {
        PoseidonOffCircuitHash::<F>::init().hash(*input)
    }

    /// Compute Poseidon hash of `input` (off-circuit), padding it with zeros if necessary.
    pub fn padded_hash<F: FieldExt>(input: &[F]) -> F {
        hash(&pad(input, F::ZERO))
    }
}

pub mod circuit {
    use alloc::{vec, vec::Vec};

    use halo2_proofs::{
        circuit::{Layouter, Region},
        plonk::{Advice, Column, Error},
    };

    use crate::{
        consts::merkle_constants::{ARITY, WIDTH},
        poseidon::PoseidonCircuitHash,
        AssignedCell, FieldExt,
    };

    pub type PoseidonConfig<F> = halo2_poseidon::poseidon::Pow5Config<F, WIDTH, ARITY>;
    pub type PoseidonChip<F> = halo2_poseidon::poseidon::Pow5Chip<F, WIDTH, ARITY>;

    /// Compute Poseidon hash of `input` (in-circuit).
    pub fn hash<F: FieldExt>(
        layouter: &mut impl Layouter<F>,
        poseidon_chip: PoseidonChip<F>,
        input: [AssignedCell<F>; ARITY],
    ) -> Result<AssignedCell<F>, Error> {
        PoseidonCircuitHash::<F>::init(poseidon_chip, layouter.namespace(|| "Hash init"))?
            .hash(layouter.namespace(|| "Poseidon hash"), input)
    }

    pub fn padded_hash<F: FieldExt>(
        layouter: &mut impl Layouter<F>,
        poseidon_chip: PoseidonChip<F>,
        input: &[&AssignedCell<F>],
    ) -> Result<AssignedCell<F>, Error> {
        let padded_input = prepare_padded_input(layouter, poseidon_chip.clone(), input)?;
        hash(layouter, poseidon_chip, padded_input)
    }

    fn assign_padded_input<F: FieldExt>(
        mut region: Region<F>,
        state: [Column<Advice>; WIDTH],
        input: &[&AssignedCell<F>],
    ) -> Result<[AssignedCell<F>; ARITY], Error> {
        let mut cells: Vec<AssignedCell<F>> = vec![];

        for (i, column) in state.iter().enumerate().take(ARITY) {
            let newborn = if i < input.len() {
                input[i].copy_advice(|| alloc::format!("input [{i}]"), &mut region, *column, 0)?
            } else {
                region.assign_advice_from_constant(|| "zero pad", *column, 0, F::ZERO)?
            };
            cells.push(newborn);
        }
        Ok(cells.try_into().expect("Safe unwrap"))
    }

    fn prepare_padded_input<F: FieldExt>(
        layouter: &mut impl Layouter<F>,
        poseidon: PoseidonChip<F>,
        input: &[&AssignedCell<F>],
    ) -> Result<[AssignedCell<F>; ARITY], Error> {
        layouter.assign_region(
            || "Padded hash",
            |region| assign_padded_input(region, poseidon.config.state, input),
        )
    }
}
