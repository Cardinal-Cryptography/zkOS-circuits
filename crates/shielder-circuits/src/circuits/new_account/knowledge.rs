use halo2_proofs::circuit::Value;
use macros::embeddable;
use rand_core::RngCore;

use crate::{
    chips::note::off_circuit::balances_from_native_balance,
    embed::Embed,
    new_account::{circuit::NewAccountCircuit, NewAccountInstance},
    note_hash,
    poseidon::off_circuit::hash,
    version::NOTE_VERSION,
    Field, Note, ProverKnowledge, PublicInputProvider, F,
};

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "NewAccountProverKnowledge<Value<F>>",
    impl_generics = "",
    embedded = "NewAccountProverKnowledge<crate::AssignedCell>"
)]
pub struct NewAccountProverKnowledge<T> {
    pub id: T,
    pub nullifier: T,
    pub trapdoor: T,
    pub initial_deposit: T,
}

impl ProverKnowledge for NewAccountProverKnowledge<F> {
    type Circuit = NewAccountCircuit;
    type PublicInput = NewAccountInstance;

    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        Self {
            id: F::random(&mut *rng),
            nullifier: F::random(&mut *rng),
            trapdoor: F::random(rng),
            initial_deposit: F::ONE,
        }
    }

    fn create_circuit(&self) -> Self::Circuit {
        NewAccountCircuit(NewAccountProverKnowledge {
            id: Value::known(self.id),
            trapdoor: Value::known(self.trapdoor),
            nullifier: Value::known(self.nullifier),
            initial_deposit: Value::known(self.initial_deposit),
        })
    }
}

impl PublicInputProvider<NewAccountInstance> for NewAccountProverKnowledge<F> {
    fn compute_public_input(&self, instance_id: NewAccountInstance) -> F {
        match instance_id {
            NewAccountInstance::HashedNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier,
                trapdoor: self.trapdoor,
                balances: balances_from_native_balance(self.initial_deposit),
            }),
            NewAccountInstance::HashedId => hash(&[self.id]),
            NewAccountInstance::InitialDeposit => self.initial_deposit,
        }
    }
}
