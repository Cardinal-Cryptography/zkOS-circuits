use core::array;

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::{ColumnPool, SynthesisPhase},
    consts::POSEIDON_RATE,
    embed::Embed,
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, Fr, Value,
};

const CHUNK_SIZE: usize = POSEIDON_RATE - 1;

/// Chip that is able to calculate the shortlist hash
#[derive(Clone, Debug)]
pub struct ShortlistHashChip<const N: usize> {
    poseidon: PoseidonChip,
}

/// Represents a (short) list of field elements.
///
/// Hashing is implemented by chaining fixed-sized chunks of the list.
#[derive(Copy, Clone, Debug)]
pub struct Shortlist<T, const N: usize> {
    items: [T; N],
}

impl<const N: usize> Embed for Shortlist<Value, N> {
    type Embedded = Shortlist<AssignedCell, N>;

    fn embed(
        &self,
        layouter: &mut impl Layouter<Fr>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        annotation: impl Into<alloc::string::String>,
    ) -> Result<Self::Embedded, Error> {
        let items = self.items.embed(layouter, advice_pool, annotation)?;
        Ok(Shortlist { items })
    }
}

impl<T, const N: usize> From<[T; N]> for Shortlist<T, N> {
    fn from(items: [T; N]) -> Self {
        Self { items }
    }
}

impl<T: Default, const N: usize> Default for Shortlist<T, N> {
    fn default() -> Self {
        Self {
            items: array::from_fn(|_| T::default()),
        }
    }
}

impl<T, const N: usize> Shortlist<T, N> {
    pub fn new(items: [T; N]) -> Self {
        const { assert!(N > 0 && N % CHUNK_SIZE == 0) };
        Self { items }
    }

    pub fn items(&self) -> &[T; N] {
        &self.items
    }

    pub fn map<R>(self, f: impl Fn(T) -> R) -> Shortlist<R, N> {
        Shortlist {
            items: self.items.map(f),
        }
    }
}

pub mod off_circuit {
    use super::{Shortlist, CHUNK_SIZE};
    use crate::{poseidon::off_circuit::hash, Fr};

    #[allow(dead_code)]
    pub fn shortlist_hash<const N: usize>(shortlist: &Shortlist<Fr, N>) -> Fr {
        let mut last = Fr::zero();
        let mut input = [Fr::zero(); CHUNK_SIZE + 1];
        let items = &shortlist.items[..];

        for chunk in items.chunks(CHUNK_SIZE).rev() {
            let size = input.len() - 1;
            input[size] = last;
            input[0..size].copy_from_slice(chunk);
            last = hash(&input);
        }

        last
    }
}

impl<const N: usize> ShortlistHashChip<N> {
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    /// Calculate the shortlist hash by chunking the shortlist by POSEIDON_RATE - 1
    /// and chaining the hashes together.
    pub fn shortlist_hash(
        &self,
        layouter: &mut impl Layouter<Fr>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
        shortlist: &Shortlist<AssignedCell, N>,
    ) -> Result<AssignedCell, Error> {
        let zero_cell = layouter.assign_region(
            || "Shortlist placeholder (zero)",
            |mut region| {
                region.assign_advice_from_constant(
                    || "Shortlist placeholder (zero)",
                    column_pool.get_any(),
                    0,
                    Fr::zero(),
                )
            },
        )?;

        let mut last = zero_cell.clone();
        let items = &shortlist.items[..];

        for chunk in items.chunks(CHUNK_SIZE).rev() {
            let mut input: [AssignedCell; CHUNK_SIZE + 1] = array::from_fn(|_| zero_cell.clone());
            let size = input.len() - 1;
            input[size] = last;
            input[0..size].clone_from_slice(chunk);
            last = hash(
                &mut layouter.namespace(|| "Shortlist Hash"),
                self.poseidon.clone(),
                input,
            )?;
        }

        Ok(last)
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use assert2::assert;
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::MockProver,
        plonk::{Circuit, Column, Instance},
    };

    use super::*;
    use crate::{
        column_pool::PreSynthesisPhase, config_builder::ConfigsBuilder, embed::Embed, poseidon, Fr,
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
            // 1. Embed shortlist items and hash.
            let items: [AssignedCell; N] = self
                .0
                .items
                .map(|balance| balance.embed(&mut layouter, &pool, "balance").unwrap());
            let shortlist = Shortlist { items };
            let embedded_hash = chip.shortlist_hash(&mut layouter, &pool, &shortlist)?;

            // 2. Compare hash with public input.
            layouter.constrain_instance(embedded_hash.cell(), instance, 0)
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
        let expected_hash = off_circuit::shortlist_hash(&input);
        let result = MockProver::run(7, &ShortlistCircuit(input), vec![vec![expected_hash]])
            .expect("Mock prover should run successfully")
            .verify();

        assert!(result.is_ok());
    }

    #[test]
    fn test_chained_hash() {
        let input: Shortlist<Fr, 12> = Shortlist::new(array::from_fn(|i| (i as u64).into()));

        let hash_chunk_2 = poseidon::off_circuit::hash(&[
            Fr::from(6),
            Fr::from(7),
            Fr::from(8),
            Fr::from(9),
            Fr::from(10),
            Fr::from(11),
            Fr::from(0),
        ]);
        let expected_hash = crate::poseidon::off_circuit::hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            hash_chunk_2,
        ]);

        assert!(expected_hash == off_circuit::shortlist_hash(&input));
    }

    #[test]
    fn test_single_chunk_hash() {
        let input: Shortlist<Fr, 6> = Shortlist::new(array::from_fn(|i| (i as u64).into()));

        let expected_hash = crate::poseidon::off_circuit::hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::zero(),
        ]);

        assert!(expected_hash == off_circuit::shortlist_hash(&input));
    }
}
