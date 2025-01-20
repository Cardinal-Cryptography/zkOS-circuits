use halo2_proofs::{circuit::Layouter, plonk::Error};

use crate::{
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, F,
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
        F,
    };

    pub fn mac(input: &MacInput<F>) -> Mac<F> {
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
pub struct MacChip {
    poseidon: PoseidonChip,
}

impl MacChip {
    /// Create a new `MacChip`.
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    /// Calculate the MAC as `(r, H(r, key))`.
    pub fn mac(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &MacInput<AssignedCell>,
    ) -> Result<Mac<AssignedCell>, Error> {
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
    use std::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use crate::{
        chips::{
            mac::{off_circuit, Mac, MacChip, MacInput},
            shortlist_hash::ShortlistHashChip,
        },
        column_pool::ColumnPool,
        config_builder::ConfigsBuilder,
        embed::Embed,
        F,
    };

    #[derive(Clone, Debug, Default)]
    struct MacCircuit(MacInput<F>);

    impl Circuit<F> for MacCircuit {
        type Config = (ColumnPool<Advice>, MacChip, Column<Instance>);
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // Enable public input.
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // Register Poseidon.
            let configs_builder = ConfigsBuilder::new(meta).with_poseidon();
            // Create MAC chip.
            let mac = MacChip::new(configs_builder.poseidon_chip());

            (configs_builder.advice_pool(), mac, instance)
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

    fn input(key: impl Into<F>, r: impl Into<F>) -> MacInput<F> {
        MacInput {
            key: key.into(),
            r: r.into(),
        }
    }

    fn verify(input: MacInput<F>, expected_mac: Mac<F>) -> Result<(), Vec<String>> {
        MockProver::run(
            6,
            &MacCircuit(input),
            vec![vec![expected_mac.r, expected_mac.commitment]],
        )
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
    fn correct_input_passes() {
        let input = input(41, 42);
        let mac = off_circuit::mac(&input);

        assert!(verify(input, mac).is_ok());
    }

    #[test]
    fn incorrect_mac_fails() {
        let expected_mac = off_circuit::mac(&input(1, 42));
        let input = input(41, 42);

        let mut errors = verify(input, expected_mac)
            .expect_err("Verification should fail")
            .into_iter();

        assert!(errors
            .any(|error| error
                .contains("Equality constraint not satisfied by cell (Column('Instance'")));
        assert!(errors
            .any(|error| error
                .contains("Equality constraint not satisfied by cell (Column('Advice'")));
    }

    #[test]
    fn incorrect_r_fails() {
        let mut expected_mac = off_circuit::mac(&input(41, 42));
        expected_mac.r += F::one();
        let input = input(41, 42);

        let mut errors = verify(input, expected_mac)
            .expect_err("Verification should fail")
            .into_iter();

        assert!(errors
            .any(|error| error
                .contains("Equality constraint not satisfied by cell (Column('Instance'")));
        assert!(errors
            .any(|error| error
                .contains("Equality constraint not satisfied by cell (Column('Advice'")));
    }
}
