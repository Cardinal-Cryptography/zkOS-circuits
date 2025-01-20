use core::array;

use halo2_proofs::circuit::Value;
use macros::embeddable;
use rand::Rng;
use rand_core::RngCore;

use crate::{
    chips::{
        balances_increase::off_circuit::increase_balances, shortlist_hash::Shortlist,
        token_index::off_circuit::index_from_indicators,
    },
    consts::{
        merkle_constants::{ARITY, NOTE_TREE_HEIGHT},
        NONCE_UPPER_LIMIT, NUM_TOKENS,
    },
    deposit::{circuit::DepositCircuit, DepositInstance},
    embed::Embed,
    merkle::generate_example_path_with_given_leaf,
    note_hash,
    poseidon::off_circuit::hash,
    version::NOTE_VERSION,
    Field, Note, ProverKnowledge, PublicInputProvider, F,
};

/// Stores values needed to compute example inputs for `DepositCircuit`. Provides a function
/// to create such inputs.
///
/// Some of the fields of this struct are private inputs, some are public inputs,
/// and some do not appear as inputs at all, but are just intermediate advice values.
#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "DepositProverKnowledge<Value<F>>",
    impl_generics = "",
    embedded = "DepositProverKnowledge<crate::AssignedCell>"
)]
pub struct DepositProverKnowledge<F> {
    // Old note
    pub id: F,
    pub nullifier_old: F,
    pub trapdoor_old: F,
    pub balances_old: Shortlist<F, NUM_TOKENS>,

    // Merkle proof
    pub path: [[F; ARITY]; NOTE_TREE_HEIGHT],

    // New note
    pub nullifier_new: F,
    pub trapdoor_new: F,

    // `token_indicators[i] = 1` if token i is deposited, 0 otherwise.
    // Exactly one entry is 1, the rest are 0.
    pub token_indicators: Shortlist<F, NUM_TOKENS>,

    // Nonce for id_hiding
    pub nonce: F,

    pub deposit_value: F,
}

impl ProverKnowledge for DepositProverKnowledge<F> {
    type Circuit = DepositCircuit;
    type PublicInput = DepositInstance;

    /// Creates a random example with correct inputs. All values are random except for the deposit
    /// amount and the old account balances.
    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        let id = F::random(&mut *rng);
        let nonce = F::from(rng.gen_range(0..NONCE_UPPER_LIMIT) as u64);

        let nullifier_old = F::random(&mut *rng);
        let trapdoor_old = F::random(&mut *rng);
        let balances_old = Shortlist::new(array::from_fn(|i| F::from((i + 10) as u64)));
        let h_note_old = note_hash(&Note {
            version: NOTE_VERSION,
            id,
            nullifier: nullifier_old,
            trapdoor: trapdoor_old,
            balances: balances_old,
        });
        let (_, path) = generate_example_path_with_given_leaf(h_note_old, &mut *rng);
        let token_indicators = Shortlist::new(array::from_fn(|i| F::from((i == 0) as u64)));
        Self {
            id,
            nonce,
            nullifier_old,
            trapdoor_old,
            balances_old,
            path,
            nullifier_new: F::random(&mut *rng),
            trapdoor_new: F::random(rng),
            deposit_value: F::ONE,
            token_indicators,
        }
    }

    fn create_circuit(&self) -> Self::Circuit {
        DepositCircuit(DepositProverKnowledge {
            trapdoor_new: Value::known(self.trapdoor_new),
            trapdoor_old: Value::known(self.trapdoor_old),
            nullifier_new: Value::known(self.nullifier_new),
            nullifier_old: Value::known(self.nullifier_old),
            balances_old: self.balances_old.map(Value::known),
            id: Value::known(self.id),
            nonce: Value::known(self.nonce),
            path: self.path.map(|level| level.map(Value::known)),
            deposit_value: Value::known(self.deposit_value),
            token_indicators: self.token_indicators.map(Value::known),
        })
    }
}

impl PublicInputProvider<DepositInstance> for DepositProverKnowledge<F> {
    fn compute_public_input(&self, instance_id: DepositInstance) -> F {
        match instance_id {
            DepositInstance::IdHiding => hash(&[hash(&[self.id]), self.nonce]),
            DepositInstance::MerkleRoot => hash(&self.path[NOTE_TREE_HEIGHT - 1]),
            DepositInstance::HashedOldNullifier => hash(&[self.nullifier_old]),
            DepositInstance::HashedNewNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier_new,
                trapdoor: self.trapdoor_new,
                balances: increase_balances(
                    &self.balances_old,
                    &self.token_indicators,
                    self.deposit_value,
                ),
            }),
            DepositInstance::DepositValue => self.deposit_value,
            DepositInstance::TokenIndex => index_from_indicators(&self.token_indicators),
        }
    }
}
