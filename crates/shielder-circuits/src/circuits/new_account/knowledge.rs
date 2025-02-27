use alloc::{vec, vec::Vec};

use macros::embeddable;
use rand_core::RngCore;

use crate::{
    chips::{
        el_gamal::{self, ElGamalEncryptionInput},
        sym_key,
    },
    consts::FIELD_BITS,
    curve_arithmetic::{self, GrumpkinPointAffine},
    embed::Embed,
    new_account::{circuit::NewAccountCircuit, NewAccountFullInstance},
    note_hash,
    poseidon::off_circuit::hash,
    version::NOTE_VERSION,
    Field, Fr, Note, ProverKnowledge, PublicInputProvider, Value,
};

#[derive(Clone, Debug)]
#[embeddable(
    receiver = "NewAccountProverKnowledge<Value>",
    embedded = "NewAccountProverKnowledge<crate::AssignedCell>"
)]
pub struct NewAccountProverKnowledge<T> {
    pub id: T,
    pub nullifier: T,
    pub trapdoor: T,
    pub initial_deposit: T,
    pub token_address: T,
    pub encryption_salt: [T; FIELD_BITS],
    pub anonymity_revoker_public_key: GrumpkinPointAffine<T>,
}

impl<T: Default + Copy> Default for NewAccountProverKnowledge<T> {
    fn default() -> Self {
        Self {
            id: T::default(),
            nullifier: T::default(),
            trapdoor: T::default(),
            initial_deposit: T::default(),
            token_address: T::default(),
            encryption_salt: [T::default(); FIELD_BITS],
            anonymity_revoker_public_key: GrumpkinPointAffine::default(),
        }
    }
}

impl ProverKnowledge for NewAccountProverKnowledge<Fr> {
    type Circuit = NewAccountCircuit;
    type PublicInput = NewAccountFullInstance;

    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        Self {
            id: curve_arithmetic::generate_user_id(Fr::random(&mut *rng).to_bytes()),
            nullifier: Fr::random(&mut *rng),
            trapdoor: Fr::random(&mut *rng),
            initial_deposit: Fr::ONE,
            token_address: Fr::ZERO,
            encryption_salt: core::array::from_fn(|_| Fr::ONE),
            anonymity_revoker_public_key: GrumpkinPointAffine::random(rng),
        }
    }

    fn create_circuit(&self) -> Self::Circuit {
        NewAccountCircuit(NewAccountProverKnowledge {
            id: Value::known(self.id),
            trapdoor: Value::known(self.trapdoor),
            nullifier: Value::known(self.nullifier),
            initial_deposit: Value::known(self.initial_deposit),
            token_address: Value::known(self.token_address),
            encryption_salt: self.encryption_salt.map(Value::known),
            anonymity_revoker_public_key: GrumpkinPointAffine::new(
                Value::known(self.anonymity_revoker_public_key.x),
                Value::known(self.anonymity_revoker_public_key.y),
            ),
        })
    }
}

impl PublicInputProvider<NewAccountFullInstance> for NewAccountProverKnowledge<Fr> {
    fn serialize_public_input(&self) -> Vec<Fr> {
        let inner_hash = hash(&[
            self.compute_public_input(NewAccountFullInstance::SymKeyEncryptionCiphertext1X),
            self.compute_public_input(NewAccountFullInstance::SymKeyEncryptionCiphertext1Y),
            self.compute_public_input(NewAccountFullInstance::SymKeyEncryptionCiphertext2X),
            self.compute_public_input(NewAccountFullInstance::SymKeyEncryptionCiphertext2Y),
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
        ]);
        let outer_hash = hash(&[
            self.compute_public_input(NewAccountFullInstance::HashedNote),
            self.compute_public_input(NewAccountFullInstance::HashedId),
            self.compute_public_input(NewAccountFullInstance::InitialDeposit),
            self.compute_public_input(NewAccountFullInstance::TokenAddress),
            self.compute_public_input(NewAccountFullInstance::AnonymityRevokerPublicKeyX),
            self.compute_public_input(NewAccountFullInstance::AnonymityRevokerPublicKeyY),
            inner_hash,
        ]);
        vec![outer_hash]
    }

    fn compute_public_input(&self, instance_id: NewAccountFullInstance) -> Fr {
        let symmetric_key = sym_key::off_circuit::derive(self.id);
        let y = curve_arithmetic::quadratic_residue_given_x_affine(symmetric_key)
            .sqrt()
            .expect("element has a square root");

        let (c1, c2) = el_gamal::off_circuit::encrypt(ElGamalEncryptionInput {
            message: GrumpkinPointAffine::new(symmetric_key, y).into(),
            public_key: self.anonymity_revoker_public_key.into(),
            salt_le_bits: self.encryption_salt,
        });

        let ciphertext1: GrumpkinPointAffine<Fr> = c1.into();
        let ciphertext2: GrumpkinPointAffine<Fr> = c2.into();

        let hashed_note = note_hash(&Note {
            version: NOTE_VERSION,
            id: self.id,
            nullifier: self.nullifier,
            trapdoor: self.trapdoor,
            account_balance: self.initial_deposit,
            token_address: self.token_address,
        });

        match instance_id {
            NewAccountFullInstance::HashedNote => hashed_note,
            NewAccountFullInstance::HashedId => hash(&[self.id]),
            NewAccountFullInstance::InitialDeposit => self.initial_deposit,
            NewAccountFullInstance::TokenAddress => self.token_address,
            NewAccountFullInstance::AnonymityRevokerPublicKeyX => {
                self.anonymity_revoker_public_key.x
            }
            NewAccountFullInstance::AnonymityRevokerPublicKeyY => {
                self.anonymity_revoker_public_key.y
            }
            NewAccountFullInstance::SymKeyEncryptionCiphertext1X => ciphertext1.x,
            NewAccountFullInstance::SymKeyEncryptionCiphertext1Y => ciphertext1.y,
            NewAccountFullInstance::SymKeyEncryptionCiphertext2X => ciphertext2.x,
            NewAccountFullInstance::SymKeyEncryptionCiphertext2Y => ciphertext2.y,
        }
    }
}
