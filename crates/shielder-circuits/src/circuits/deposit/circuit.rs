use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};

use crate::{
    chips::token_index::TokenIndexChip,
    circuits::deposit::{chip::DepositChip, knowledge::DepositProverKnowledge},
    column_pool::{ColumnPool, PreSynthesisPhase},
    config_builder::ConfigsBuilder,
    deposit::{DepositConstraints, DepositInstance},
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    synthesizer::create_synthesizer,
    todo::Todo,
    Fr, Value,
};

#[derive(Clone, Debug, Default)]
pub struct DepositCircuit(pub DepositProverKnowledge<Value>);

impl Circuit<Fr> for DepositCircuit {
    type Config = (DepositChip, ColumnPool<Advice, PreSynthesisPhase>);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let public_inputs = InstanceWrapper::<DepositInstance>::new(meta);

        let configs_builder = ConfigsBuilder::new(meta)
            .with_balances_increase()
            .with_merkle(public_inputs.narrow())
            .with_range_check();

        let token_index = TokenIndexChip::new(public_inputs.narrow());

        (
            DepositChip {
                public_inputs,
                poseidon: configs_builder.poseidon_chip(),
                merkle: configs_builder.merkle_chip(),
                range_check: configs_builder.range_check_chip(),
                balances_increase: configs_builder.balances_increase_chip(),
                token_index,
            },
            configs_builder.finish(),
        )
    }

    fn synthesize(
        &self,
        (main_chip, column_pool): Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut synthesizer = create_synthesizer(synthesizer);
        let mut todo = Todo::<DepositConstraints>::new();
        let knowledge = self.0.embed(&mut synthesizer, "DepositProverKnowledge")?;

        main_chip.check_old_note(&mut synthesizer, &knowledge, &mut todo)?;
        main_chip.check_old_nullifier(&mut synthesizer, &knowledge, &mut todo)?;
        main_chip.check_new_note(&mut synthesizer, &knowledge, &mut todo)?;
        main_chip.check_id_hiding(&mut synthesizer, &knowledge, &mut todo)?;
        main_chip.check_token_index(&mut synthesizer, &knowledge, &mut todo)?;
        todo.assert_done()
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
    use rand::{rngs::SmallRng, SeedableRng};
    use rand_core::OsRng;

    use crate::{
        chips::{
            balances_increase::off_circuit::increase_balances,
            token_index::off_circuit::index_from_indicators,
        },
        circuits::{
            deposit::knowledge::DepositProverKnowledge,
            merkle::generate_example_path_with_given_leaf,
            test_utils::{
                expect_instance_permutation_failures, expect_prover_success_and_run_verification,
                run_full_pipeline, PublicInputProviderExt,
            },
        },
        deposit::DepositInstance::{self, *},
        note_hash,
        poseidon::off_circuit::hash,
        version::NOTE_VERSION,
        Note, ProverKnowledge, PublicInputProvider,
    };

    #[test]
    fn passes_if_inputs_correct() {
        run_full_pipeline::<DepositProverKnowledge<Fr>>();
    }

    #[test]
    fn fails_if_merkle_proof_uses_wrong_note() {
        let mut pk = DepositProverKnowledge::random_correct_example(&mut OsRng);

        let (merkle_root, path) =
            generate_example_path_with_given_leaf(Fr::random(&mut OsRng), &mut OsRng);
        pk.path = path;
        let pub_input = pk.with_substitution(MerkleRoot, |_| merkle_root);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    #[test]
    fn fails_if_incorrect_h_nullifier_is_published() {
        let pk = DepositProverKnowledge::random_correct_example(&mut OsRng);
        let pub_input = pk.with_substitution(HashedOldNullifier, |hash| hash + Fr::ONE);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    #[test]
    fn fails_if_h_note_new_is_not_the_hash_of_appropriate_witnesses() {
        let pk = DepositProverKnowledge::random_correct_example(&mut OsRng);
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
            let mut pk = DepositProverKnowledge::random_correct_example(&mut rng);

            // Build the old note.
            let h_note_old = note_hash(&Note {
                version: NOTE_VERSION,
                id: pk.id,
                nullifier: pk.nullifier_old,
                trapdoor: pk.trapdoor_old,
                balances: pk.balances_old,
            }) + modification /* Modification here! */;
            let h_nullifier_old = hash(&[pk.nullifier_old]);

            // Build the Merkle proof.
            let (merkle_root, path) = generate_example_path_with_given_leaf(h_note_old, &mut rng);
            pk.path = path;

            // Build the new account state.
            let balances_new =
                increase_balances(&pk.balances_old, &pk.token_indicators, pk.deposit_value);

            // Build the new note.
            let h_note_new = note_hash(&Note {
                version: NOTE_VERSION,
                id: pk.id,
                nullifier: pk.nullifier_new,
                trapdoor: pk.trapdoor_new,
                balances: balances_new,
            });

            let pub_input = |instance: DepositInstance| match instance {
                IdHiding => hash(&[hash(&[pk.id]), pk.nonce]),
                MerkleRoot => merkle_root,
                HashedOldNullifier => h_nullifier_old,
                HashedNewNote => h_note_new,
                DepositValue => pk.deposit_value,
                TokenIndex => index_from_indicators(&pk.token_indicators),
            };

            assert_eq!(
                expect_prover_success_and_run_verification(
                    pk.create_circuit(),
                    &pub_input.serialize_public_input()
                )
                .is_ok(),
                verify_is_expected_to_pass
            );
        }
    }
    #[test]
    fn passes_if_deposited_nonnative_token() {
        let mut rng = SmallRng::from_seed([42; 32]);
        let mut pk = DepositProverKnowledge::random_correct_example(&mut rng);

        pk.token_indicators = [0, 1, 0, 0, 0, 0].map(Fr::from);
        let pub_input = pk.serialize_public_input();

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_ok()
        );

        // Manually verify the new note hash used in the circuit.
        let mut hash_input = [Fr::ZERO; 7];
        for i in 0..6 {
            hash_input[i] = pk.balances_old.items()[i];
        }
        hash_input[1] += pk.deposit_value;
        let new_balances_hash = hash(&hash_input);
        let new_note_hash = hash(&[
            Fr::ZERO, // Note version.
            pk.id,
            pk.nullifier_new,
            pk.trapdoor_new,
            new_balances_hash,
        ]);
        assert_eq!(new_note_hash, pub_input[3]);

        // Verify the token index.
        assert_eq!(Fr::ONE, pub_input[5]);
    }

    #[test]
    fn fails_if_token_index_pub_input_incorrect() {
        let mut rng = SmallRng::from_seed([42; 32]);
        let pk = DepositProverKnowledge::random_correct_example(&mut rng);

        let mut pub_input = pk.serialize_public_input();
        pub_input[5] += Fr::ONE;

        let failures = expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input)
            .expect_err("Verification must fail");

        expect_instance_permutation_failures(&failures, "Token index", 5);
    }

    // TODO: Add more tests, as the above tests do not cover all the logic that should be covered.
}
