use macros::embeddable;
use rand::Rng;
use rand_core::RngCore;

use crate::{
    chips::sym_key,
    consts::{
        merkle_constants::{ARITY, NOTE_TREE_HEIGHT},
        NONCE_UPPER_LIMIT,
    },
    deposit::{circuit::DepositCircuit, DepositInstance},
    embed::Embed,
    merkle::generate_example_path_with_given_leaf,
    note_hash,
    poseidon::off_circuit::hash,
    version::NOTE_VERSION,
    Field, Fr, Note, ProverKnowledge, PublicInputProvider, Value,
};

/// Stores values needed to compute example inputs for `DepositCircuit`. Provides a function
/// to create such inputs.
///
/// Some of the fields of this struct are private inputs, some are public inputs,
/// and some do not appear as inputs at all, but are just intermediate advice values.
#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "DepositProverKnowledge<Value>",
    embedded = "DepositProverKnowledge<crate::AssignedCell>"
)]
pub struct DepositProverKnowledge<T> {
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

    // Nonce for id_hiding
    pub nonce: T,
    // Salt for MAC.
    pub mac_salt: T,

    pub deposit_value: T,
}

impl ProverKnowledge for DepositProverKnowledge<Fr> {
    type Circuit = DepositCircuit;
    type PublicInput = DepositInstance;

    /// Creates a random example with correct inputs. All values are random except for the deposit
    /// amount and the old account balances.
    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        let id = Fr::random(&mut *rng);
        let nonce = Fr::from(rng.gen_range(0..NONCE_UPPER_LIMIT) as u64);

        let nullifier_old = Fr::random(&mut *rng);
        let trapdoor_old = Fr::random(&mut *rng);
        let account_old_balance = Fr::from(10);
        let h_note_old = note_hash(&Note {
            version: NOTE_VERSION,
            id,
            nullifier: nullifier_old,
            trapdoor: trapdoor_old,
            account_balance: account_old_balance,
        });
        let (_, path) = generate_example_path_with_given_leaf(h_note_old, &mut *rng);
        Self {
            id,
            nonce,
            nullifier_old,
            trapdoor_old,
            account_old_balance,
            path,
            nullifier_new: Fr::random(&mut *rng),
            trapdoor_new: Fr::random(&mut *rng),
            deposit_value: Fr::ONE,
            mac_salt: Fr::random(rng),
        }
    }

    fn create_circuit(&self) -> Self::Circuit {
        DepositCircuit(DepositProverKnowledge {
            trapdoor_new: Value::known(self.trapdoor_new),
            trapdoor_old: Value::known(self.trapdoor_old),
            nullifier_new: Value::known(self.nullifier_new),
            nullifier_old: Value::known(self.nullifier_old),
            account_old_balance: Value::known(self.account_old_balance),
            id: Value::known(self.id),
            nonce: Value::known(self.nonce),
            path: self.path.map(|level| level.map(Value::known)),
            deposit_value: Value::known(self.deposit_value),
            mac_salt: Value::known(self.mac_salt),
        })
    }
}

impl PublicInputProvider<DepositInstance> for DepositProverKnowledge<Fr> {
    fn compute_public_input(&self, instance_id: DepositInstance) -> Fr {
        let sym_key = sym_key::off_circuit::derive(self.id);

        match instance_id {
            DepositInstance::IdHiding => hash(&[hash(&[self.id]), self.nonce]),
            DepositInstance::MerkleRoot => hash(&self.path[NOTE_TREE_HEIGHT - 1]),
            DepositInstance::HashedOldNullifier => hash(&[self.nullifier_old]),
            DepositInstance::HashedNewNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier_new,
                trapdoor: self.trapdoor_new,
                account_balance: self.account_old_balance + self.deposit_value,
            }),
            DepositInstance::DepositValue => self.deposit_value,
            DepositInstance::MacSalt => self.mac_salt,
            DepositInstance::MacHash => hash(&[self.mac_salt, sym_key]),
        }
    }
}
