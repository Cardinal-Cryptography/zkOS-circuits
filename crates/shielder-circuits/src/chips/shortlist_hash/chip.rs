use core::array;

use halo2_proofs::plonk::Error;

use crate::{
    chips::shortlist_hash::{Shortlist, CHUNK_SIZE},
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    AssignedCell, Fr,
};

/// Chip that is able to calculate the shortlist hash
#[derive(Clone, Debug)]
pub struct ShortlistHashChip<const N: usize> {
    poseidon: PoseidonChip,
}

impl<const N: usize> ShortlistHashChip<N> {
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    /// Calculate the shortlist hash by chunking the shortlist by POSEIDON_RATE - 1
    /// and chaining the hashes together.
    pub fn shortlist_hash(
        &self,
        synthesizer: &mut impl Synthesizer,
        shortlist: &Shortlist<AssignedCell, N>,
    ) -> Result<AssignedCell, Error> {
        let zero_cell = synthesizer.assign_constant("Shortlist placeholder (zero)", Fr::zero())?;
        let mut last = zero_cell.clone();
        let items = &shortlist.items[..];

        for chunk in items.chunks(CHUNK_SIZE).rev() {
            let mut input: [AssignedCell; CHUNK_SIZE + 1] = array::from_fn(|_| zero_cell.clone());
            input[CHUNK_SIZE] = last;
            input[0..CHUNK_SIZE].clone_from_slice(chunk);
            // TODO: APPLY GATE
            last = hash(synthesizer, self.poseidon.clone(), input)?;
        }

        Ok(last)
    }
}

#[cfg(test)]
mod chip_tests {
    use std::{array, vec};

    use assert2::assert;
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, Error, Instance},
    };

    use crate::{
        chips::shortlist_hash::{chip::ShortlistHashChip, off_circuit::shortlist_hash, Shortlist},
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        embed::Embed,
        synthesizer::create_synthesizer,
        AssignedCell, Fr,
    };

    #[derive(Clone, Debug, Default)]
    struct ShortlistCircuit<const N: usize>(Shortlist<Fr, N>);

    impl<const N: usize> Circuit<Fr> for ShortlistCircuit<N> {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            ShortlistHashChip<N>,
            Column<Instance>,
        );
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fr>) -> Self::Config {
            // Enable public input.
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // Register Poseidon.
            let configs_builder = ConfigsBuilder::new(meta).with_poseidon();
            // Create Shortlist chip.
            let chip = ShortlistHashChip::new(configs_builder.poseidon_chip());

            (configs_builder.finish(), chip, instance)
        }

        fn synthesize(
            &self,
            (pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let pool = pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &pool);

            // 1. Embed shortlist items and hash.
            let items: [AssignedCell; N] = self.0.items.embed(&mut synthesizer, "balance")?;
            let shortlist = Shortlist { items };
            let embedded_hash = chip.shortlist_hash(&mut synthesizer, &shortlist)?;

            // 2. Compare hash with public input.
            synthesizer.constrain_instance(embedded_hash.cell(), instance, 0)
        }
    }

    #[test]
    fn test_hash_compatibility_chained() {
        test_hash_compatibility(Shortlist::<Fr, 12>::new(array::from_fn(|i| {
            (i as u64).into()
        })));
    }

    #[test]
    fn test_hash_compatibility_single_chunk() {
        test_hash_compatibility(Shortlist::<Fr, 6>::new(array::from_fn(|i| {
            (i as u64).into()
        })));
    }

    fn test_hash_compatibility<const N: usize>(input: Shortlist<Fr, N>) {
        let expected_hash = shortlist_hash(&input);
        let result = MockProver::run(7, &ShortlistCircuit(input), vec![vec![expected_hash]])
            .expect("Mock prover should run successfully")
            .verify();

        assert!(result.is_ok());
    }
}
