use macros::embeddable;
use rand_core::RngCore;

use crate::{
    chips::{
        asymmetric_encryption::{self, AsymPublicKey, ElGamalEncryptionInput},
        sym_key,
    },
    curve_arithmetic::{self, field_element_to_le_bits, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    new_account::{circuit::NewAccountCircuit, NewAccountInstance},
    note_hash,
    poseidon::off_circuit::hash,
    version::NOTE_VERSION,
    Field, Fr, Note, ProverKnowledge, PublicInputProvider, Value,
};

#[derive(Clone, Debug, Default)]
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
    pub anonymity_revoker_public_key: AsymPublicKey<T>,
}

impl ProverKnowledge for NewAccountProverKnowledge<Fr> {
    type Circuit = NewAccountCircuit;
    type PublicInput = NewAccountInstance;

    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        Self {
            id: curve_arithmetic::generate_user_id(Fr::random(&mut *rng).to_bytes()),
            nullifier: Fr::random(&mut *rng),
            trapdoor: Fr::random(&mut *rng),
            initial_deposit: Fr::ONE,
            token_address: Fr::ZERO,
            anonymity_revoker_public_key: AsymPublicKey::random(rng),
        }
    }

    fn create_circuit(&self) -> Self::Circuit {
        NewAccountCircuit(NewAccountProverKnowledge {
            id: Value::known(self.id),
            trapdoor: Value::known(self.trapdoor),
            nullifier: Value::known(self.nullifier),
            initial_deposit: Value::known(self.initial_deposit),
            token_address: Value::known(self.token_address),
            anonymity_revoker_public_key: AsymPublicKey::new(
                Value::known(self.anonymity_revoker_public_key.x),
                Value::known(self.anonymity_revoker_public_key.y),
            ),
        })
    }
}

impl PublicInputProvider<NewAccountInstance> for NewAccountProverKnowledge<Fr> {
    fn compute_public_input(&self, instance_id: NewAccountInstance) -> Fr {
        let symmetric_key = sym_key::off_circuit::derive(self.id);
        let y = curve_arithmetic::quadratic_residue_given_x_affine(symmetric_key)
            .sqrt()
            .expect("element has a square root");

        let point = GrumpkinPointAffine::new(symmetric_key, y).into();
        // TODO: in production there should be a separate trapdoor field element for the symmetric key encryption
        let trapdoor_le_bits = field_element_to_le_bits(self.trapdoor);

        let input = ElGamalEncryptionInput {
            message: point,
            public_key: self.anonymity_revoker_public_key,
            trapdoor_le_bits,
        };

        // TODO : take these two points to affine coords
        let (ciphertext1, ciphertext2) = asymmetric_encryption::off_circuit::encrypt(input);

        match instance_id {
            NewAccountInstance::HashedNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier,
                trapdoor: self.trapdoor,
                account_balance: self.initial_deposit,
                token_address: self.token_address,
            }),
            NewAccountInstance::HashedId => hash(&[self.id]),
            NewAccountInstance::InitialDeposit => self.initial_deposit,
            NewAccountInstance::TokenAddress => self.token_address,
            NewAccountInstance::AnonymityRevokerPublicKeyX => self.anonymity_revoker_public_key.x,
            NewAccountInstance::AnonymityRevokerPublicKeyY => self.anonymity_revoker_public_key.y,
            NewAccountInstance::SymKeyEncryptionCiphertext1X => todo!(),
            NewAccountInstance::SymKeyEncryptionCiphertext1Y => todo!(),
            NewAccountInstance::SymKeyEncryptionCiphertext2X => todo!(),
            NewAccountInstance::SymKeyEncryptionCiphertext2Y => todo!(),
            // NewAccountInstance::SymKeyEncryption => asymmetric_encryption::off_circuit::encrypt(
            //     self.anonymity_revoker_public_key,
            //     sym_key::off_circuit::derive(self.id),
            // ),
        }
    }
}
