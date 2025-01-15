use core::array;

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::ColumnPool,
    consts::POSEIDON_RATE,
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, F,
};

struct AssertShortlistSizeCorrect<const N: usize>;

impl<const N: usize> AssertShortlistSizeCorrect<N> {
    const OK: () = assert!(
        N > 0 && N % (POSEIDON_RATE - 1) == 0,
        "Invalid compile time constants - N must be positive and divisible by POSEIDON_RATE - 1"
    );
}

/// Chip that is able to calculate the shortlist hash
#[derive(Clone, Debug)]
pub struct ShortlistChip<const N: usize> {
    poseidon: PoseidonChip,
    advice_pool: ColumnPool<Advice>,
}

/// Represents a (short) list of field elements.
///
/// Hashing is implemented by chaining fixed-sized chunks of the list.
#[derive(Copy, Clone, Debug)]
pub struct Shortlist<F, const N: usize> {
    pub items: [F; N],
}

impl<const N: usize> Default for Shortlist<F, N> {
    fn default() -> Self {
        Self {
            items: array::from_fn(|_| F::default()),
        }
    }
}

pub mod off_circuit {
    use crate::{
        chips::shortlist::{AssertShortlistSizeCorrect, Shortlist},
        consts::POSEIDON_RATE,
        poseidon::off_circuit::hash,
        F,
    };

    #[allow(dead_code)]
    pub fn shortlist_hash<const N: usize>(shortlist: &Shortlist<F, N>) -> F {
        let () = AssertShortlistSizeCorrect::<N>::OK;

        let mut last = F::zero();
        let mut input = [F::zero(); POSEIDON_RATE];
        let items = &shortlist.items[..];

        for chunk in items.chunks(POSEIDON_RATE - 1).rev() {
            let size = input.len() - 1;
            input[size] = last;
            input[0..size].copy_from_slice(chunk);
            last = hash(&input);
        }

        last
    }
}

impl<const N: usize> ShortlistChip<N> {
    pub fn new(poseidon: PoseidonChip, advice_pool: ColumnPool<Advice>) -> Self {
        Self {
            poseidon,
            advice_pool,
        }
    }

    /// Calculate the shortlist hash by chunking the shortlist by POSEIDON_RATE - 1
    /// and chaining the hashes together.
    pub fn shortlist(
        &self,
        layouter: &mut impl Layouter<F>,
        shortlist: &Shortlist<AssignedCell, N>,
    ) -> Result<AssignedCell, Error> {
        let () = AssertShortlistSizeCorrect::<N>::OK;

        let zero_cell = layouter.assign_region(
            || "Shortlist placeholder (zero)",
            |mut region| {
                region.assign_advice_from_constant(
                    || "Shortlist placeholder (zero)",
                    self.advice_pool.get_any(),
                    0,
                    F::zero(),
                )
            },
        )?;

        let mut last = zero_cell.clone();
        let items = &shortlist.items[..];

        for chunk in items.chunks(POSEIDON_RATE - 1).rev() {
            let mut input: [AssignedCell; POSEIDON_RATE] = array::from_fn(|_| zero_cell.clone());
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
    use std::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::MockProver,
        plonk::{Circuit, Column, Instance},
    };

    use super::*;
    use crate::{config_builder::ConfigsBuilder, embed::Embed, F};

    #[derive(Clone, Debug, Default)]
    struct ShortlistCircuit<const N: usize>(Shortlist<F, N>);

    impl<const N: usize> Circuit<F> for ShortlistCircuit<N> {
        type Config = (ColumnPool<Advice>, ShortlistChip<N>, Column<Instance>);
        type FloorPlanner = V1;

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            // Enable public input.
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // Register Poseidon.
            let (pool, poseidon) = ConfigsBuilder::new(meta).poseidon().resolve_poseidon();
            // Create Shortlist chip.
            let chip = ShortlistChip::new(poseidon, pool.clone());

            (pool, chip, instance)
        }

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn synthesize(
            &self,
            (pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // 1. Embed shortlist items and hash.
            let items: [AssignedCell; N] = self
                .0
                .items
                .map(|balance| balance.embed(&mut layouter, &pool, "balance").unwrap());
            let shortlist = Shortlist { items };
            let embedded_hash = chip.shortlist(&mut layouter, &shortlist)?;

            // 2. Compare hash with public input.
            layouter.constrain_instance(embedded_hash.cell(), instance, 0)
        }
    }

    #[test]
    fn test_hash_compatibility() -> Result<(), Vec<String>> {
        let input: Shortlist<_, 12> = Shortlist {
            items: array::from_fn(|i| (i as u64).into()),
        };
        let expected_hash = off_circuit::shortlist_hash(&input);

        MockProver::run(21, &ShortlistCircuit(input), vec![vec![expected_hash]])
            .expect("Mock prover should run successfully")
            .verify()
            .map_err(|errors| {
                errors
                    .into_iter()
                    .map(|failure| failure.to_string())
                    .collect()
            })
    }

    #[test]
    fn test_chained_hash() {
        let input: Shortlist<F, 12> = Shortlist {
            items: array::from_fn(|i| (i as u64).into()),
        };

        let hash_chunk2 = crate::poseidon::off_circuit::hash(&[
            F::from(6),
            F::from(7),
            F::from(8),
            F::from(9),
            F::from(10),
            F::from(11),
            F::from(0),
        ]);
        let expected_hash = crate::poseidon::off_circuit::hash(&[
            F::from(0),
            F::from(1),
            F::from(2),
            F::from(3),
            F::from(4),
            F::from(5),
            hash_chunk2,
        ]);

        assert!(expected_hash == off_circuit::shortlist_hash(&input));
    }
}
