use halo2_proofs::circuit::Value;
use macros::embeddable;
use rand::Rng;
use rand_core::RngCore;

use crate::{
    consts::{
        merkle_constants::{ARITY, NOTE_TREE_HEIGHT},
        MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK, NONCE_UPPER_LIMIT,
    },
    embed::Embed,
    merkle::generate_example_path_with_given_leaf,
    note_hash,
    poseidon::off_circuit::hash,
    version::NOTE_VERSION,
    withdraw::{circuit::WithdrawCircuit, WithdrawInstance},
    FieldExt, Note, ProverKnowledge, PublicInputProvider,
};

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "WithdrawProverKnowledge<Value<F>, CHUNK_SIZE>",
    impl_generics = "<F: FieldExt, const CHUNK_SIZE: usize>",
    embedded = "WithdrawProverKnowledge<crate::AssignedCell<F>, CHUNK_SIZE>"
)]
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
    pub fn compute_intermediate_values(&self) -> IntermediateValues<Value<F>> {
        IntermediateValues {
            new_account_balance: self.account_old_balance - self.withdrawal_value,
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
            WithdrawInstance::IdHiding => hash(&[hash(&[self.id]), self.nonce]),
            WithdrawInstance::MerkleRoot => hash(&self.path[NOTE_TREE_HEIGHT - 1]),
            WithdrawInstance::HashedOldNullifier => hash(&[self.nullifier_old]),
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
#[embeddable(
    receiver = "IntermediateValues<Value<F>>",
    impl_generics = "<F: FieldExt>",
    embedded = "IntermediateValues<crate::AssignedCell<F>>"
)]
pub struct IntermediateValues<F> {
    /// Account balance after the withdrawal is made.
    pub new_account_balance: F,
}
