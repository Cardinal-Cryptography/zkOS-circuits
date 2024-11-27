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
        NONCE_UPPER_LIMIT,
    },
    deposit::{circuit::DepositCircuit, DepositInstance},
    merkle::generate_example_path_with_given_leaf,
    note_hash,
    poseidon::off_circuit::hash,
    synthesis_helpers::{assign_2d_advice_array, assign_values_to_advice},
    utils::padded_hash,
    version::NOTE_VERSION,
    AssignedCell, FieldExt, Note, ProverKnowledge, PublicInputProvider,
};

/// Stores values needed to compute example inputs for `DepositCircuit`. Provides a function
/// to create such inputs.
///
/// Some of the fields of this struct are private inputs, some are public inputs,
/// and some do not appear as inputs at all, but are just intermediate advice values.
#[derive(Clone, Debug, Default)]
pub struct DepositProverKnowledge<F, const CHUNK_SIZE: usize> {
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

    pub deposit_value: F,
}

impl<F: FieldExt, const CHUNK_SIZE: usize> DepositProverKnowledge<Value<F>, CHUNK_SIZE> {
    pub fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
    ) -> Result<DepositProverKnowledge<AssignedCell<F>, CHUNK_SIZE>, Error> {
        let [trapdoor_new, trapdoor_old, nullifier_new, nullifier_old, account_old_balance, id, nonce, value] =
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
                    (self.deposit_value, "value"),
                ],
            )?;
        let path = layouter.assign_region(
            || "path witness",
            |region| assign_2d_advice_array(region, self.path, advice_pool.get_array()),
        )?;

        Ok(DepositProverKnowledge {
            trapdoor_new,
            trapdoor_old,
            nullifier_new,
            nullifier_old,
            account_old_balance,
            id,
            nonce,
            path,
            deposit_value: value,
        })
    }

    pub fn compute_intermediate_values(&self) -> IntermediateValues<Value<F>> {
        IntermediateValues {
            account_new_balance: self.account_old_balance + self.deposit_value,
        }
    }
}

impl<F: FieldExt, const CHUNK_SIZE: usize> ProverKnowledge<F>
    for DepositProverKnowledge<F, CHUNK_SIZE>
{
    type Circuit = DepositCircuit<F, CHUNK_SIZE>;
    type PublicInput = DepositInstance;

    /// Creates a random example with correct inputs. All values are random except for the deposit
    /// amount and the old account balance, which are set to 1 and 9 respectively.
    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        let id = F::random(&mut *rng);
        let nonce = F::from(rng.gen_range(0..NONCE_UPPER_LIMIT) as u64);

        let nullifier_old = F::random(&mut *rng);
        let trapdoor_old = F::random(&mut *rng);
        let account_old_balance = F::from(9);
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
            nullifier_new: F::random(&mut *rng),
            trapdoor_new: F::random(rng),
            deposit_value: F::ONE,
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
        })
    }
}

impl<F: FieldExt, const CHUNK_SIZE: usize> PublicInputProvider<DepositInstance, F>
    for DepositProverKnowledge<F, CHUNK_SIZE>
{
    fn compute_public_input(&self, instance_id: DepositInstance) -> F {
        match instance_id {
            DepositInstance::IdHiding => padded_hash(&[padded_hash(&[self.id]), self.nonce]),
            DepositInstance::MerkleRoot => hash(&self.path[NOTE_TREE_HEIGHT - 1]),
            DepositInstance::HashedOldNullifier => padded_hash(&[self.nullifier_old]),
            DepositInstance::HashedNewNote => note_hash(&Note {
                version: NOTE_VERSION,
                id: self.id,
                nullifier: self.nullifier_new,
                trapdoor: self.trapdoor_new,
                account_balance: self.account_old_balance + self.deposit_value,
            }),
            DepositInstance::DepositValue => self.deposit_value,
        }
    }
}

/// Stores values that are a result of intermediate computations.
#[derive(Clone, Debug, Default)]
pub struct IntermediateValues<F> {
    /// Account balance after the deposit is made.
    pub account_new_balance: F,
}

impl<F: FieldExt> IntermediateValues<Value<F>> {
    pub fn embed(
        self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
    ) -> Result<IntermediateValues<AssignedCell<F>>, Error> {
        let account_new_balance = layouter.assign_region(
            || "account_new_balance",
            |mut region| {
                region.assign_advice(
                    || "account_new_balance",
                    advice_pool.get_any(),
                    0,
                    || self.account_new_balance,
                )
            },
        )?;

        Ok(IntermediateValues {
            account_new_balance,
        })
    }
}
