use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    circuits::withdraw::chip::WithdrawChip,
    config_builder::ConfigsBuilder,
    instance_wrapper::InstanceWrapper,
    todo::Todo,
    withdraw::{WithdrawConstraints, WithdrawInstance, WithdrawProverKnowledge},
    FieldExt,
};

#[derive(Clone, Debug, Default)]
pub struct WithdrawCircuit<F, const CHUNK_SIZE: usize>(
    pub WithdrawProverKnowledge<Value<F>, CHUNK_SIZE>,
);

impl<F: FieldExt, const CHUNK_SIZE: usize> Circuit<F> for WithdrawCircuit<F, CHUNK_SIZE> {
    type Config = WithdrawChip<F, CHUNK_SIZE>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Default::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let public_inputs = InstanceWrapper::<WithdrawInstance>::new(meta);

        let configs_builder = ConfigsBuilder::new(meta)
            .sum()
            .poseidon()
            .merkle(public_inputs.narrow())
            .range_check();

        let range_check = configs_builder.resolve_range_check_chip();

        let (advice_pool, poseidon, merkle) = configs_builder.resolve_merkle();
        let (_, sum_chip) = configs_builder.resolve_sum_chip();

        WithdrawChip {
            advice_pool,
            public_inputs,
            poseidon,
            merkle,
            range_check,
            sum_chip,
        }
    }

    fn synthesize(
        &self,
        main_chip: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut todo = Todo::<WithdrawConstraints>::new();
        let knowledge = self.0.embed(&mut layouter, &main_chip.advice_pool)?;
        let intermediate = self
            .0
            .compute_intermediate_values()
            .embed(&mut layouter, &main_chip.advice_pool)?;

        main_chip.check_old_note(&mut layouter, &knowledge, &mut todo)?;
        main_chip.check_old_nullifier(&mut layouter, &knowledge, &mut todo)?;
        main_chip.check_new_note(&mut layouter, &knowledge, &intermediate, &mut todo)?;
        main_chip.check_commitment(&mut layouter, &knowledge, &mut todo)?;
        main_chip.check_id_hiding(&mut layouter, &knowledge, &mut todo)?;

        todo.assert_done()
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
    use rand_core::OsRng;

    use crate::{
        circuits::{
            merkle::generate_example_path_with_given_leaf,
            test_utils::{
                expect_prover_success_and_run_verification,
                expect_prover_success_and_run_verification_on_separate_pub_input,
                run_full_pipeline, PublicInputProviderExt,
            },
            utils::padded_hash,
            withdraw::knowledge::WithdrawProverKnowledge,
        },
        consts::{MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK, RANGE_PROOF_CHUNK_SIZE},
        generate_keys_with_min_k, generate_proof, generate_setup_params, note_hash,
        version::NOTE_VERSION,
        withdraw::{circuit::WithdrawCircuit, WithdrawInstance, WithdrawInstance::*},
        Field, Note, ProverKnowledge, PublicInputProvider, F, MAX_K,
    };

    #[test]
    fn passes_if_inputs_correct() {
        run_full_pipeline::<WithdrawProverKnowledge<F, RANGE_PROOF_CHUNK_SIZE>>();
    }

    #[test]
    fn fails_if_merkle_proof_uses_wrong_note() {
        let mut pk = WithdrawProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(
            &mut OsRng,
        );

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
        let pk = WithdrawProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(
            &mut OsRng,
        );
        let pub_input = pk.with_substitution(HashedOldNullifier, |hash| hash + Fr::ONE);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    #[test]
    fn fails_if_h_note_new_is_not_the_hash_of_appropriate_witnesses() {
        let pk = WithdrawProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(
            &mut OsRng,
        );
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
        for (modification, verify_is_expected_to_pass) in [(F::ONE, false), (F::ZERO, true)] {
            let mut pk =
                WithdrawProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(
                    &mut rng,
                );

            // Build the old note.
            pk.nullifier_old = F::random(rng);
            pk.trapdoor_old = F::random(rng);
            pk.account_old_balance = F::from_u128(MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK);
            let h_note_old = note_hash(&Note {
                version: NOTE_VERSION,
                id: pk.id,
                nullifier: pk.nullifier_old,
                trapdoor: pk.trapdoor_old,
                account_balance: pk.account_old_balance,
            }) + modification /* Modification here! */;
            let h_nullifier_old = padded_hash(&[pk.nullifier_old]);

            // Build the Merkle proof.
            let (merkle_root, path) = generate_example_path_with_given_leaf(h_note_old, &mut rng);
            pk.path = path;

            // Build the new account state.
            let value = F::ONE;
            let account_balance_new = pk.account_old_balance - value;

            // Build the new note.
            pk.nullifier_new = F::random(rng);
            pk.trapdoor_new = F::random(rng);
            let h_note_new = note_hash(&Note {
                version: NOTE_VERSION,
                id: pk.id,
                nullifier: pk.nullifier_new,
                trapdoor: pk.trapdoor_new,
                account_balance: account_balance_new,
            });

            let pub_input = |instance: WithdrawInstance| match instance {
                IdHiding => padded_hash(&[padded_hash(&[pk.id]), pk.nonce]),
                MerkleRoot => merkle_root,
                HashedOldNullifier => h_nullifier_old,
                HashedNewNote => h_note_new,
                WithdrawalValue => value,
                Commitment => pk.commitment,
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
        let pk = WithdrawProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(
            &mut OsRng,
        );

        let prove_public_input = pk.serialize_public_input();
        assert!(expect_prover_success_and_run_verification(
            pk.create_circuit(),
            &prove_public_input,
        )
        .is_ok());

        let verify_public_input = pk.with_substitution(Commitment, |c| c + F::ONE);
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
        let mut pk = WithdrawProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(
            &mut OsRng,
        );

        // `F::-1` should fail the range check.
        pk.withdrawal_value = -F::ONE;

        let params = generate_setup_params(MAX_K, &mut OsRng);
        let (params, _, key, _) =
            generate_keys_with_min_k::<WithdrawCircuit<_, RANGE_PROOF_CHUNK_SIZE>>(params).unwrap();
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
