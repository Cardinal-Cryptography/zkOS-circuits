use halo2_proofs::plonk::ErrorFront;

use crate::{
    consts::SYM_KEY_SALT,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    AssignedCell,
};

pub mod off_circuit {
    use crate::{consts::SYM_KEY_SALT, poseidon::off_circuit::hash, Fr};

    pub fn derive(id: Fr) -> Fr {
        hash(&[id, *SYM_KEY_SALT])
    }
}

#[derive(Clone, Debug)]
pub struct SymKeyChip {
    poseidon: PoseidonChip,
}

impl SymKeyChip {
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    pub fn derive(
        &self,
        synthesizer: &mut impl Synthesizer,
        id: AssignedCell,
    ) -> Result<AssignedCell, ErrorFront> {
        let salt = synthesizer.assign_constant("SymKey salt", *SYM_KEY_SALT)?;
        hash(synthesizer, self.poseidon.clone(), [id, salt])
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
        plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
    };
    use rand_core::OsRng;

    use crate::{
        chips::sym_key::{off_circuit, SymKeyChip},
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        embed::Embed,
        synthesizer::create_synthesizer,
        Field, Fr,
    };

    #[derive(Clone, Debug, Default)]
    struct SymKeyCircuit {
        id: Fr,
    }

    impl Circuit<Fr> for SymKeyCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            SymKeyChip,
            Column<Instance>,
        );
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            // Enable public input.
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // Register Poseidon.
            let configs_builder = ConfigsBuilder::new(meta).with_poseidon();
            // Create SymKey chip.
            let sym_key = SymKeyChip::new(configs_builder.poseidon_chip());

            (configs_builder.finish(), sym_key, instance)
        }

        fn synthesize(
            &self,
            (pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            let pool = pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &pool);
            // 1. Embed id.
            let id = self.id.embed(&mut synthesizer, "id")?;

            // 2. Derive symmetric key.
            let sym_key = chip.derive(&mut synthesizer, id)?;

            // 3. Compare with public input.
            synthesizer.constrain_instance(sym_key.cell(), instance, 0)
        }
    }

    fn verify(id: impl Into<Fr>, expected_sym_key: impl Into<Fr>) -> Result<(), Vec<String>> {
        MockProver::run(
            6,
            &SymKeyCircuit { id: id.into() },
            vec![vec![expected_sym_key.into()]],
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
        let id = Fr::random(OsRng);
        let sym_key = off_circuit::derive(id);
        assert!(verify(id, sym_key).is_ok());
    }

    #[test]
    fn incorrect_sym_key_fails() {
        let expected_sym_key = off_circuit::derive(Fr::from(41));
        let another_id = Fr::from(42);

        let mut errors = verify(another_id, expected_sym_key)
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
