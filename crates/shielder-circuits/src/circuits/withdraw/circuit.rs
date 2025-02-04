use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};

use crate::{
    circuits::withdraw::chip::WithdrawChip,
    column_pool::{ColumnPool, PreSynthesisPhase},
    config_builder::ConfigsBuilder,
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    synthesizer::create_synthesizer,
    withdraw::{WithdrawInstance, WithdrawProverKnowledge},
    Fr, Value,
};

#[derive(Clone, Debug, Default)]
pub struct WithdrawCircuit(pub WithdrawProverKnowledge<Value>);

impl Circuit<Fr> for WithdrawCircuit {
    type Config = (WithdrawChip, ColumnPool<Advice, PreSynthesisPhase>);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Default::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let public_inputs = InstanceWrapper::<WithdrawInstance>::new(meta);

        let configs_builder = ConfigsBuilder::new(meta)
            .with_merkle(public_inputs.narrow())
            .with_range_check()
            .with_note(public_inputs.narrow());

        (
            WithdrawChip {
                public_inputs,
                poseidon: configs_builder.poseidon_chip(),
                merkle: configs_builder.merkle_chip(),
                range_check: configs_builder.range_check_chip(),
                sum_chip: configs_builder.sum_chip(),
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
        let knowledge = self.0.embed(&mut synthesizer, "WithdrawProverKnowledge")?;

        main_chip.check_old_note(&mut synthesizer, &knowledge)?;
        main_chip.check_old_nullifier(&mut synthesizer, &knowledge)?;
        main_chip.check_new_note(&mut synthesizer, &knowledge)?;
        main_chip.check_commitment(&mut synthesizer, &knowledge)?;
        main_chip.check_id_hiding(&mut synthesizer, &knowledge)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::halo2curves::bn256::Fr;
    use rand_core::OsRng;

    use crate::{
        circuits::{
            merkle::generate_example_path_with_given_leaf,
            test_utils::{
                expect_prover_success_and_run_verification,
                expect_prover_success_and_run_verification_on_separate_pub_input,
                run_full_pipeline, PublicInputProviderExt,
            },
            withdraw::knowledge::WithdrawProverKnowledge,
        },
        generate_keys_with_min_k, generate_proof, generate_setup_params, note_hash,
        poseidon::off_circuit::hash,
        version::NOTE_VERSION,
        withdraw::{
            circuit::WithdrawCircuit,
            WithdrawInstance::{self, *},
        },
        Field, Note, ProverKnowledge, PublicInputProvider, MAX_K,
    };

    #[test]
    fn passes_if_inputs_correct() {
        run_full_pipeline::<WithdrawProverKnowledge<Fr>>();
    }

    #[test]
    fn fails_if_merkle_proof_uses_wrong_note() {
        let mut pk = WithdrawProverKnowledge::random_correct_example(&mut OsRng);

        let (merkle_root, path) =
            generate_example_path_with_given_leaf(Fr::random(&mut OsRng), &mut OsRng);
        pk.path = path;
        let pub_input = pk.with_substitution(MerkleRoot, |_| merkle_root);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input,).is_err()
        );
    }

    #[test]
    fn fails_if_incorrect_h_nullifier_is_published() {
        let pk = WithdrawProverKnowledge::random_correct_example(&mut OsRng);
        let pub_input = pk.with_substitution(HashedOldNullifier, |hash| hash + Fr::ONE);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    #[test]
    fn fails_if_h_note_new_is_not_the_hash_of_appropriate_witnesses() {
        let pk = WithdrawProverKnowledge::random_correct_example(&mut OsRng);
        let pub_input = pk.with_substitution(HashedNewNote, |hash| hash + Fr::ONE);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    #[test]
    fn fails_if_h_note_old_is_not_the_hash_of_appropriate_witnesses() {
        let mut rng = OsRng;

        // First we break the witness and expect verification failure, then we run with correct
        // witnesses and expect verification success. If we just did the former, it would be easy
        // to introduce a bug to this test and the test would pass without checking anything.
        for (modification, verify_is_expected_to_pass) in [(Fr::ONE, false), (Fr::ZERO, true)] {
            let mut pk = WithdrawProverKnowledge::random_correct_example(&mut rng);

            // Build the old note.
            let h_note_old = note_hash(&Note {
                version: NOTE_VERSION,
                id: pk.id,
                nullifier: pk.nullifier_old,
                trapdoor: pk.trapdoor_old,
                account_balance: pk.account_old_balance,
                token_address: pk.token_address,
            }) + modification /* Modification here! */;
            let h_nullifier_old = hash(&[pk.nullifier_old]);

            // Build the Merkle proof.
            let (merkle_root, path) = generate_example_path_with_given_leaf(h_note_old, &mut rng);
            pk.path = path;

            // Build the new account state.
            let account_balance_new = pk.account_old_balance - pk.withdrawal_value;

            // Build the new note.
            let h_note_new = note_hash(&Note {
                version: NOTE_VERSION,
                id: pk.id,
                nullifier: pk.nullifier_new,
                trapdoor: pk.trapdoor_new,
                account_balance: account_balance_new,
                token_address: pk.token_address,
            });

            let pub_input = |instance: WithdrawInstance| match instance {
                IdHiding => hash(&[hash(&[pk.id]), pk.nonce]),
                MerkleRoot => merkle_root,
                HashedOldNullifier => h_nullifier_old,
                HashedNewNote => h_note_new,
                WithdrawalValue => pk.withdrawal_value,
                Commitment => pk.commitment,
                TokenAddress => pk.token_address,
            };

            assert_eq!(
                expect_prover_success_and_run_verification(
                    pk.create_circuit(),
                    &pub_input.serialize_public_input(),
                )
                .is_ok(),
                verify_is_expected_to_pass
            );
        }
    }

    #[test]
    fn fails_if_commitment_provided_during_verify_is_not_one_provided_during_proof() {
        let pk = WithdrawProverKnowledge::random_correct_example(&mut OsRng);

        let prove_public_input = pk.serialize_public_input();
        assert!(expect_prover_success_and_run_verification(
            pk.create_circuit(),
            &prove_public_input,
        )
        .is_ok());

        let verify_public_input = pk.with_substitution(Commitment, |c| c + Fr::ONE);
        assert!(
            expect_prover_success_and_run_verification_on_separate_pub_input(
                pk.create_circuit(),
                &prove_public_input,
                &verify_public_input,
            )
            .is_err()
        );
    }

    #[test]
    #[should_panic]
    fn fails_if_new_balance_overflowed() {
        let mut pk = WithdrawProverKnowledge::random_correct_example(&mut OsRng);

        // `F::-1` should fail the range check.
        pk.withdrawal_value = -Fr::ONE;

        let params = generate_setup_params(MAX_K, &mut OsRng);
        let (params, _, key, _) = generate_keys_with_min_k::<WithdrawCircuit>(params).unwrap();
        generate_proof(
            &params,
            &key,
            pk.create_circuit(),
            &pk.serialize_public_input(),
            &mut OsRng,
        );
    }

    // TODO: Add more tests, as the above tests do not cover all the logic that should be covered.
}
