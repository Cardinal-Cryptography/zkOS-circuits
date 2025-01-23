use halo2_proofs::halo2curves::ff::PrimeField;
use macros::embeddable;
use rand::Rng;
use rand_core::RngCore;

use crate::{
    chips::note::off_circuit::balances_from_native_balance,
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
    Field, Fr, Note, ProverKnowledge, PublicInputProvider, Value,
};

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "WithdrawProverKnowledge<Value>",
    impl_generics = "",
    embedded = "WithdrawProverKnowledge<crate::AssignedCell>"
)]
pub struct WithdrawProverKnowledge<T> {
    pub withdrawal_value: T,

    // Additional public parameters that need to be included in proof
    pub commitment: T,

    // Old note
    pub id: T,
    pub nullifier_old: T,
    pub trapdoor_old: T,
    pub account_old_balance: T,

    // Merkle proof
    pub path: [[T; ARITY]; NOTE_TREE_HEIGHT],

    // New note
    pub nullifier_new: T,
    pub trapdoor_new: T,

    // nonce for id_hiding
    pub nonce: T,
}

impl WithdrawProverKnowledge<Value> {
    pub fn compute_intermediate_values(&self) -> IntermediateValues<Value> {
        IntermediateValues {
            new_account_balance: self.account_old_balance - self.withdrawal_value,
        }
    }
}

impl ProverKnowledge for WithdrawProverKnowledge<Fr> {
    type Circuit = WithdrawCircuit;
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
        let id = Fr::random(&mut *rng);
        let nonce = Fr::from(rng.gen_range(0..NONCE_UPPER_LIMIT) as u64);
        let nullifier_old = Fr::random(&mut *rng);
        let trapdoor_old = Fr::random(&mut *rng);

        let account_old_balance = Fr::from_u128(MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK);
        let h_note_old = note_hash(&Note {
            version: NOTE_VERSION,
            id,
            nullifier: nullifier_old,
            trapdoor: trapdoor_old,
            balances: balances_from_native_balance(account_old_balance),
        });

        let (_, path) = generate_example_path_with_given_leaf(h_note_old, &mut *rng);

        Self {
            withdrawal_value: Fr::ONE,
            commitment: Fr::random(&mut *rng),
            id,
            nonce,
            nullifier_old,
            trapdoor_old,
            account_old_balance,
            path,
            nullifier_new: Fr::random(&mut *rng),
            trapdoor_new: Fr::random(rng),
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

impl PublicInputProvider<WithdrawInstance> for WithdrawProverKnowledge<Fr> {
    fn compute_public_input(&self, instance_id: WithdrawInstance) -> Fr {
        match instance_id {
            WithdrawInstance::IdHiding => hash(&[hash(&[self.id]), self.nonce]),
            WithdrawInstance::MerkleRoot => hash(&self.path[NOTE_TREE_HEIGHT - 1]),
            WithdrawInstance::HashedOldNullifier => hash(&[self.nullifier_old]),
            WithdrawInstance::HashedNewNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier_new,
                trapdoor: self.trapdoor_new,
                balances: balances_from_native_balance(
                    self.account_old_balance - self.withdrawal_value,
                ),
            }),
            WithdrawInstance::WithdrawalValue => self.withdrawal_value,
            WithdrawInstance::Commitment => self.commitment,
        }
    }
}

/// Stores values that are a result of intermediate computations.
#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "IntermediateValues<Value>",
    impl_generics = "",
    embedded = "IntermediateValues<crate::AssignedCell>"
)]
pub struct IntermediateValues<T> {
    /// Account balance after the withdrawal is made.
    pub new_account_balance: T,
}
