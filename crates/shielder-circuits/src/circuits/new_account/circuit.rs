use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, ErrorFront},
};

use crate::{
    circuits::new_account::{chip::NewAccountChip, knowledge::NewAccountProverKnowledge},
    column_pool::{ColumnPool, PreSynthesisPhase},
    config_builder::ConfigsBuilder,
    embed::Embed,
    gates::{is_point_on_curve_affine::IsPointOnCurveAffineGate, Gate},
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
            .with_note(public_inputs.narrow())
            .with_is_quadratic_residue_chip();

        (
            NewAccountChip {
                public_inputs,
                poseidon: configs_builder.poseidon_chip(),
                note: configs_builder.note_chip(),
                is_quadratic_residue: configs_builder.is_quadratic_residue_chip(),
            },
            configs_builder.finish(),
        )
    }

    fn synthesize(
        &self,
        (main_chip, column_pool): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), ErrorFront> {
        let pool = column_pool.start_synthesis();
        let mut synthesizer = create_synthesizer(&mut layouter, &pool);
        let knowledge = self
            .0
            .embed(&mut synthesizer, "NewAccountProverKnowledge")?;

        main_chip.check_note(&mut synthesizer, &knowledge)?;
        main_chip.constrain_hashed_id(&mut synthesizer, &knowledge)?;
        main_chip.constrain_sym_key_encryption(&mut synthesizer, &knowledge)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
    use rand::rngs::SmallRng;
    use rand_core::{OsRng, SeedableRng};

    use crate::{
        circuits::{
            new_account::knowledge::NewAccountProverKnowledge,
            test_utils::{
                expect_prover_success_and_run_verification, run_full_pipeline,
                PublicInputProviderExt,
            },
        },
        new_account::NewAccountInstance::*,
        poseidon::off_circuit::hash,
        test_utils::expect_instance_permutation_failures,
        ProverKnowledge, PublicInputProvider,
    };

    #[test]
    fn passes_if_inputs_correct() {
        run_full_pipeline::<NewAccountProverKnowledge<Fr>>();
    }

    #[test]
    fn passes_with_nonnative_token() {
        let mut rng = SmallRng::from_seed([42; 32]);
        let mut pk = NewAccountProverKnowledge::random_correct_example(&mut rng);
        pk.token_address = Fr::from(123);
        let pub_input = pk.serialize_public_input();

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_ok()
        );

        // Manually verify that the note is as expected.
        let mut hash_input = [Fr::ZERO; 7];
        hash_input[0] = pk.initial_deposit;
        hash_input[1] = Fr::from(123);
        let balance_hash = hash(&hash_input);
        let note_hash = hash(&[
            Fr::ZERO, // Note version.
            pk.id,
            pk.nullifier,
            pk.trapdoor,
            balance_hash,
        ]);
        assert_eq!(note_hash, pub_input[0]);
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

    #[test]
    fn fails_if_token_address_pub_input_incorrect() {
        let mut rng = SmallRng::from_seed([42; 32]);
        let pk = NewAccountProverKnowledge::random_correct_example(&mut rng);
        let pub_input = pk.with_substitution(TokenAddress, |v| v + Fr::ONE);

        let failures = expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input)
            .expect_err("Verification must fail");

        expect_instance_permutation_failures(&failures, "token_address", 1);
    }

    // TODO: Add more tests, as the above tests do not cover all the logic that should be covered.
}
