use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Error},
};
use rand::Rng;
use rand_core::RngCore;

use crate::{
    column_pool::ColumnPool,
    consts::{
        merkle_constants::{ARITY, NOTE_TREE_HEIGHT},
        MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK, NONCE_UPPER_LIMIT,
    },
    merkle::generate_example_path_with_given_leaf,
    note_hash,
    poseidon::off_circuit::hash,
    synthesis_helpers::{assign_2d_advice_array, assign_values_to_advice},
    utils::padded_hash,
    version::NOTE_VERSION,
    withdraw::{circuit::WithdrawCircuit, WithdrawInstance},
    AssignedCell, FieldExt, Note, ProverKnowledge, PublicInputProvider,
};

// Stores values needed to compute example inputs for `WithdrawCircuit`. Provides a function
// to create such inputs.
//
// Some of the fields of this struct are private inputs, some are public inputs,
// and some do not appear as inputs at all, but are just intermediate advice values.
#[allow(dead_code)] // some fields are not used, but might be useful in the future
#[derive(Clone, Debug, Default)]
pub struct WithdrawProverKnowledge<F, const CHUNK_SIZE: usize> {
    pub withdrawal_value: F,

    // Additional public parameters that need to be included in proof
    pub commitment: F,

    // Old note
    pub id: F,
    pub nullifier_old: F,
    pub trapdoor_old: F,
    pub account_old_balance: F,

    // Merkle proof
    pub path: [[F; ARITY]; NOTE_TREE_HEIGHT],

    // New note
    pub nullifier_new: F,
    pub trapdoor_new: F,

    // nonce for id_hiding
    pub nonce: F,
}

impl<F: FieldExt, const CHUNK_SIZE: usize> WithdrawProverKnowledge<Value<F>, CHUNK_SIZE> {
    pub fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
    ) -> Result<WithdrawProverKnowledge<AssignedCell<F>, CHUNK_SIZE>, Error> {
        let [trapdoor_new, trapdoor_old, nullifier_new, nullifier_old, account_old_balance, id, nonce, withdrawal_value, commitment] =
            assign_values_to_advice(
                layouter,
                advice_pool,
                "DepositPrivateInput",
                [
                    (self.trapdoor_new, "trapdoor_new"),
                    (self.trapdoor_old, "trapdoor_old"),
                    (self.nullifier_new, "nullifier_new"),
                    (self.nullifier_old, "nullifier_old"),
                    (self.account_old_balance, "account_old_balance"),
                    (self.id, "id"),
                    (self.nonce, "nonce"),
                    (self.withdrawal_value, "withdrawal_value"),
                    (self.commitment, "commitment"),
                ],
            )?;
        let path = layouter.assign_region(
            || "path witness",
            |region| assign_2d_advice_array(region, self.path, advice_pool.get_array()),
        )?;

        Ok(WithdrawProverKnowledge {
            trapdoor_new,
            trapdoor_old,
            nullifier_new,
            nullifier_old,
            account_old_balance,
            id,
            nonce,
            path,
            withdrawal_value,
            commitment,
        })
    }

    pub fn compute_intermediate_values(&self) -> IntermediateValues<Value<F>> {
        IntermediateValues {
            account_new_balance: self.account_old_balance - self.withdrawal_value,
        }
    }
}

impl<F: FieldExt, const CHUNK_SIZE: usize> ProverKnowledge<F>
    for WithdrawProverKnowledge<F, CHUNK_SIZE>
{
    type Circuit = WithdrawCircuit<F, CHUNK_SIZE>;
    type PublicInput = WithdrawInstance;

    /// TODO: Refactor this test. Having `MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK` as the only
    /// non-random, non-trivial value is inconsistent with the function name and easy to overlook.
    /// Consider moving it to a separate test. Also evaluate removing randomness completely, as
    /// random values in unit tests are generally discouraged.
    ///
    /// All initial values are random, except for the account balances, the withdrawal value,
    /// and the relayer fee.
    ///
    /// `account_old_balance` has the largest possible value that passes the range check.
    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        let id = F::random(&mut *rng);
        let nonce = F::from(rng.gen_range(0..NONCE_UPPER_LIMIT) as u64);
        let nullifier_old = F::random(&mut *rng);
        let trapdoor_old = F::random(&mut *rng);

        let account_old_balance = F::from_u128(MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK);
        let h_note_old = note_hash(&Note {
            version: NOTE_VERSION,
            id,
            nullifier: nullifier_old,
            trapdoor: trapdoor_old,
            account_balance: account_old_balance,
        });

        let (_, path) = generate_example_path_with_given_leaf(h_note_old, &mut *rng);

        Self {
            withdrawal_value: F::ONE,
            commitment: F::random(&mut *rng),
            id,
            nonce,
            nullifier_old,
            trapdoor_old,
            account_old_balance,
            path,
            nullifier_new: F::random(&mut *rng),
            trapdoor_new: F::random(rng),
        }
    }

    fn create_circuit(&self) -> Self::Circuit {
        WithdrawCircuit(WithdrawProverKnowledge {
            trapdoor_new: Value::known(self.trapdoor_new),
            trapdoor_old: Value::known(self.trapdoor_old),

            nullifier_new: Value::known(self.nullifier_new),
            nullifier_old: Value::known(self.nullifier_old),

            account_old_balance: Value::known(self.account_old_balance),

            id: Value::known(self.id),
            nonce: Value::known(self.nonce),

            path: self.path.map(|level| level.map(Value::known)),

            withdrawal_value: Value::known(self.withdrawal_value),
            commitment: Value::known(self.commitment),
        })
    }
}

impl<F: FieldExt, const CHUNK_SIZE: usize> PublicInputProvider<WithdrawInstance, F>
    for WithdrawProverKnowledge<F, CHUNK_SIZE>
{
    fn compute_public_input(&self, instance_id: WithdrawInstance) -> F {
        match instance_id {
            WithdrawInstance::IdHiding => padded_hash(&[padded_hash(&[self.id]), self.nonce]),
            WithdrawInstance::MerkleRoot => hash(&self.path[NOTE_TREE_HEIGHT - 1]),
            WithdrawInstance::HashedOldNullifier => padded_hash(&[self.nullifier_old]),
            WithdrawInstance::HashedNewNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier_new,
                trapdoor: self.trapdoor_new,
                account_balance: self.account_old_balance - self.withdrawal_value,
            }),
            WithdrawInstance::WithdrawalValue => self.withdrawal_value,
            WithdrawInstance::Commitment => self.commitment,
        }
    }
}

/// Stores values that are a result of intermediate computations.
#[derive(Clone, Debug, Default)]
pub struct IntermediateValues<F> {
    /// account balance after the withdrawal is made.
    pub account_new_balance: F,
}

impl<F: FieldExt> IntermediateValues<Value<F>> {
    pub fn embed(
        self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
    ) -> Result<IntermediateValues<AssignedCell<F>>, Error> {
        let [account_new_balance] = assign_values_to_advice(
            layouter,
            advice_pool,
            "IntermediateValues",
            [(self.account_new_balance, "account_new_balance")],
        )?;

        Ok(IntermediateValues {
            account_new_balance,
        })
    }
}
