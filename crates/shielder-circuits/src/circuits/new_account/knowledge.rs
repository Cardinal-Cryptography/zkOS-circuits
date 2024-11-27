use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Error},
};
use rand_core::RngCore;

use crate::{
    column_pool::ColumnPool,
    new_account::{circuit::NewAccountCircuit, NewAccountInstance},
    note_hash,
    synthesis_helpers::assign_values_to_advice,
    utils::padded_hash,
    version::NOTE_VERSION,
    AssignedCell, FieldExt, Note, ProverKnowledge, PublicInputProvider,
};

#[derive(Clone, Debug, Default)]
pub struct NewAccountProverKnowledge<T> {
    pub id: T,
    pub nullifier: T,
    pub trapdoor: T,
    pub initial_deposit: T,
}

impl<F: FieldExt> NewAccountProverKnowledge<Value<F>> {
    pub fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
    ) -> Result<NewAccountProverKnowledge<AssignedCell<F>>, Error> {
        let [id, nullifier, trapdoor, initial_deposit] = assign_values_to_advice(
            layouter,
            advice_pool,
            "NewAccountPrivateInput",
            [
                (self.id, "id"),
                (self.nullifier, "nullifier"),
                (self.trapdoor, "trapdoor"),
                (self.initial_deposit, "initial_deposit"),
            ],
        )?;

        Ok(NewAccountProverKnowledge {
            id,
            nullifier,
            trapdoor,
            initial_deposit,
        })
    }
}

impl<F: FieldExt> ProverKnowledge<F> for NewAccountProverKnowledge<F> {
    type Circuit = NewAccountCircuit<F>;
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

impl<F: FieldExt> PublicInputProvider<NewAccountInstance, F> for NewAccountProverKnowledge<F> {
    fn compute_public_input(&self, instance_id: NewAccountInstance) -> F {
        match instance_id {
            NewAccountInstance::HashedNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier,
                trapdoor: self.trapdoor,
                account_balance: self.initial_deposit,
            }),
            NewAccountInstance::HashedId => padded_hash(&[self.id]),
            NewAccountInstance::InitialDeposit => self.initial_deposit,
        }
    }
}
