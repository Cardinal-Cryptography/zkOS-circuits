use halo2_proofs::{circuit::Layouter, plonk::Error};

use crate::{
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, FieldExt,
};

/// Input for MAC calculation.
#[derive(Copy, Clone, Debug, Default)]
pub struct MacInput<T> {
    pub key: T,
    pub r: T,
}

/// MAC (commitment to a key accompanied by salt).
#[derive(Copy, Clone, Debug)]
pub struct Mac<T> {
    pub r: T,
    pub commitment: T,
}

pub mod off_circuit {
    use crate::{
        chips::mac::{Mac, MacInput},
        poseidon::off_circuit::hash,
        FieldExt,
    };

    pub fn mac<F: FieldExt>(input: &MacInput<F>) -> Mac<F> {
        Mac {
            r: input.r,
            commitment: hash(&[input.r, input.key]),
        }
    }
}

/// Chip that is able to calculate MAC.
///
/// Given a key `key` and a random value `r`, MAC is calculated as `(r, H(r, key))`.
#[derive(Clone, Debug)]
pub struct MacChip<F: FieldExt> {
    poseidon: PoseidonChip<F>,
}

impl<F: FieldExt> MacChip<F> {
    /// Create a new `MacChip`.
    pub fn new(poseidon: PoseidonChip<F>) -> Self {
        Self { poseidon }
    }

    /// Calculate the MAC as `(r, H(r, key))`.
    pub fn mac(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &MacInput<AssignedCell<F>>,
    ) -> Result<Mac<AssignedCell<F>>, Error> {
        let commitment = hash(
            &mut layouter.namespace(|| "MAC"),
            self.poseidon.clone(),
            [input.r.clone(), input.key.clone()],
        )?;

        Ok(Mac {
            r: input.r.clone(),
            commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use crate::{
        chips::mac::{off_circuit, MacChip, MacInput},
        column_pool::ColumnPool,
        config_builder::ConfigsBuilder,
        embed::Embed,
        run_mock_prover, F,
    };

    #[derive(Clone, Debug, Default)]
    struct MacCircuit(MacInput<F>);

    impl Circuit<F> for MacCircuit {
        type Config = (ColumnPool<Advice>, MacChip<F>, Column<Instance>);
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // Enable public input.
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // Register Poseidon.
            let (pool, poseidon) = ConfigsBuilder::new(meta).poseidon().resolve_poseidon();
            // Create MAC chip.
            let mac = MacChip::new(poseidon);

            (pool, mac, instance)
        }

        fn synthesize(
            &self,
            (pool, mac_chip, instance): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // 1. Embed key and r.
            let key = self.0.key.embed(&mut layouter, &pool, "key")?;
            let r = self.0.r.embed(&mut layouter, &pool, "r")?;

            // 2. Calculate MAC.
            let mac = mac_chip.mac(&mut layouter, &MacInput { key, r })?;

            // 3. Compare MAC with public input.
            layouter.constrain_instance(mac.r.cell(), instance, 0)?;
            layouter.constrain_instance(mac.commitment.cell(), instance, 1)
        }
    }

    #[test]
    fn correct_input_passes() {
        let input = MacInput {
            key: F::from(41),
            r: F::from(43),
        };
        let mac = off_circuit::mac(&input);

        run_mock_prover(6, &MacCircuit(input), vec![mac.r, mac.commitment]);
    }
}
