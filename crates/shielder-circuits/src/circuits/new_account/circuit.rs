use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};

use crate::{
    circuits::new_account::{chip::NewAccountChip, knowledge::NewAccountProverKnowledge},
    column_pool::{ColumnPool, PreSynthesisPhase},
    config_builder::ConfigsBuilder,
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    new_account::NewAccountInstance,
    synthesizer::create_synthesizer,
    Fr, Value,
};

#[derive(Clone, Debug, Default)]
pub struct NewAccountCircuit(pub NewAccountProverKnowledge<Value>);

impl Circuit<Fr> for NewAccountCircuit {
    type Config = (NewAccountChip, ColumnPool<Advice, PreSynthesisPhase>);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let public_inputs = InstanceWrapper::<NewAccountInstance>::new(meta);
        let configs_builder = ConfigsBuilder::new(meta)
            .with_poseidon()
            .with_note(public_inputs.narrow());

        (
            NewAccountChip {
                public_inputs,
                poseidon: configs_builder.poseidon_chip(),
                note: configs_builder.note_chip(),
            },
            configs_builder.finish(),
        )
    }

    fn synthesize(
        &self,
        (main_chip, column_pool): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let pool = column_pool.start_synthesis();
        let mut synthesizer = create_synthesizer(&mut layouter, &pool);
        let knowledge = self
            .0
            .embed(&mut synthesizer, "NewAccountProverKnowledge")?;
        main_chip.synthesize(&mut synthesizer, &knowledge)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
    use rand_core::OsRng;

    use crate::{
        circuits::{
            new_account::knowledge::NewAccountProverKnowledge,
            test_utils::{
                expect_prover_success_and_run_verification, run_full_pipeline,
                PublicInputProviderExt,
            },
        },
        new_account::NewAccountInstance::*,
        ProverKnowledge,
    };

    #[test]
    fn passes_if_inputs_correct() {
        run_full_pipeline::<NewAccountProverKnowledge<Fr>>();
    }

    #[test]
    fn fails_if_incorrect_note_is_published() {
        let pk = NewAccountProverKnowledge::random_correct_example(&mut OsRng);
        let pub_input = pk.with_substitution(HashedNote, |v| v + Fr::ONE);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    #[test]
    fn fails_if_incorrect_h_id_is_published() {
        let pk = NewAccountProverKnowledge::random_correct_example(&mut OsRng);
        let pub_input = pk.with_substitution(HashedId, |v| v + Fr::ONE);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    // TODO: Add more tests, as the above tests do not cover all the logic that should be covered.
}
