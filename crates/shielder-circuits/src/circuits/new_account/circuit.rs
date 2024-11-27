use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    circuits::new_account::{chip::NewAccountChip, knowledge::NewAccountProverKnowledge},
    config_builder::ConfigsBuilder,
    instance_wrapper::InstanceWrapper,
    new_account::{NewAccountConstraints, NewAccountInstance},
    todo::Todo,
    FieldExt,
};

#[derive(Clone, Debug, Default)]
pub struct NewAccountCircuit<F>(pub NewAccountProverKnowledge<Value<F>>);

impl<F: FieldExt> Circuit<F> for NewAccountCircuit<F> {
    type Config = NewAccountChip<F>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let public_inputs = InstanceWrapper::<NewAccountInstance>::new(meta);
        let (advice_pool, poseidon) = ConfigsBuilder::new(meta).poseidon().resolve_poseidon();

        NewAccountChip {
            advice_pool,
            public_inputs,
            poseidon,
        }
    }

    fn synthesize(
        &self,
        main_chip: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut todo = Todo::<NewAccountConstraints>::new();
        let knowledge = self.0.embed(&mut layouter, &main_chip.advice_pool)?;
        main_chip.synthesize(&mut layouter, &knowledge, &mut todo)?;
        todo.assert_done()
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
