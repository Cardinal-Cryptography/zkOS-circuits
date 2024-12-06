use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    circuits::{
        deposit::{chip::DepositChip, knowledge::DepositProverKnowledge},
        FieldExt,
    },
    config_builder::ConfigsBuilder,
    deposit::{DepositConstraints, DepositInstance},
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    todo::Todo,
};

#[derive(Clone, Debug, Default)]
pub struct DepositCircuit<F, const CHUNK_SIZE: usize>(
    pub DepositProverKnowledge<Value<F>, CHUNK_SIZE>,
);

impl<F: FieldExt, const CHUNK_SIZE: usize> Circuit<F> for DepositCircuit<F, CHUNK_SIZE> {
    type Config = DepositChip<F, CHUNK_SIZE>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let public_inputs = InstanceWrapper::<DepositInstance>::new(meta);

        let configs_builder = ConfigsBuilder::new(meta)
            .sum()
            .poseidon()
            .merkle(public_inputs.narrow())
            .range_check();

        let (advice_pool, poseidon, merkle) = configs_builder.resolve_merkle();
        let (_, sum) = configs_builder.resolve_sum_chip();

        DepositChip {
            advice_pool,
            public_inputs,
            poseidon,
            merkle,
            range_check: configs_builder.resolve_range_check(),
            sum,
        }
    }

    fn synthesize(
        &self,
        main_chip: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut todo = Todo::<DepositConstraints>::new();
        let knowledge = self.0.embed(
            &mut layouter,
            &main_chip.advice_pool,
            "DepositProverKnowledge",
        )?;
        let intermediate = self.0.compute_intermediate_values().embed(
            &mut layouter,
            &main_chip.advice_pool,
            "DepositIntermediateValues",
        )?;

        main_chip.check_old_note(&mut layouter, &knowledge, &mut todo)?;
        main_chip.check_old_nullifier(&mut layouter, &knowledge, &mut todo)?;
        main_chip.check_new_note(&mut layouter, &knowledge, &intermediate, &mut todo)?;
        main_chip.check_id_hiding(&mut layouter, &knowledge, &mut todo)?;
        todo.assert_done()
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
    use rand_core::OsRng;

    use crate::{
        circuits::{
            deposit::knowledge::DepositProverKnowledge,
            merkle::generate_example_path_with_given_leaf,
            test_utils::{
                expect_prover_success_and_run_verification, run_full_pipeline,
                PublicInputProviderExt,
            },
            utils::padded_hash,
        },
        consts::RANGE_PROOF_CHUNK_SIZE,
        deposit::{DepositInstance, DepositInstance::*},
        note_hash,
        version::NOTE_VERSION,
        Note, ProverKnowledge, PublicInputProvider,
    };

    #[test]
    fn passes_if_inputs_correct() {
        run_full_pipeline::<DepositProverKnowledge<Fr, RANGE_PROOF_CHUNK_SIZE>>();
    }

    #[test]
    fn fails_if_merkle_proof_uses_wrong_note() {
        let mut pk =
            DepositProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(&mut OsRng);

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
        let pk =
            DepositProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(&mut OsRng);
        let pub_input = pk.with_substitution(HashedOldNullifier, |hash| hash + Fr::ONE);

        assert!(
            expect_prover_success_and_run_verification(pk.create_circuit(), &pub_input).is_err()
        );
    }

    #[test]
    fn fails_if_h_note_new_is_not_the_hash_of_appropriate_witnesses() {
        let pk =
            DepositProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(&mut OsRng);
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
            let mut pk =
                DepositProverKnowledge::<_, RANGE_PROOF_CHUNK_SIZE>::random_correct_example(
                    &mut rng,
                );

            // Build the old note.
            pk.nullifier_old = Fr::random(rng);
            pk.trapdoor_old = Fr::random(rng);
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
            let deposit_value = Fr::ONE;
            let account_balance_new = pk.account_old_balance + deposit_value;

            // Build the new note.
            pk.nullifier_new = Fr::random(rng);
            pk.trapdoor_new = Fr::random(rng);
            let h_note_new = note_hash(&Note {
                version: NOTE_VERSION,
                id: pk.id,
                nullifier: pk.nullifier_new,
                trapdoor: pk.trapdoor_new,
                account_balance: account_balance_new,
            });

            let pub_input = |instance: DepositInstance| match instance {
                IdHiding => padded_hash(&[padded_hash(&[pk.id]), pk.nonce]),
                MerkleRoot => merkle_root,
                HashedOldNullifier => h_nullifier_old,
                HashedNewNote => h_note_new,
                DepositValue => deposit_value,
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

    // TODO: Add more tests, as the above tests do not cover all the logic that should be covered.
}
