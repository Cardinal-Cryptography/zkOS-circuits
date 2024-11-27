use core::borrow::Borrow;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Error},
};
use rand_core::RngCore;

use crate::{
    column_pool::ColumnPool,
    consts::merkle_constants::ARITY,
    merkle::{circuit::MerkleCircuit, MerkleInstance},
    poseidon::off_circuit::hash,
    synthesis_helpers::{assign_2d_advice_array, assign_values_to_advice},
    AssignedCell, FieldExt, ProverKnowledge, PublicInputProvider,
};

#[derive(Clone, Debug)]
pub struct MerkleProverKnowledge<const TREE_HEIGHT: usize, T> {
    pub leaf: T,
    pub path: [[T; ARITY]; TREE_HEIGHT],
}

impl<const TREE_HEIGHT: usize, T: Default + Copy> Default
    for MerkleProverKnowledge<TREE_HEIGHT, T>
{
    fn default() -> Self {
        Self {
            leaf: T::default(),
            path: [[T::default(); ARITY]; TREE_HEIGHT],
        }
    }
}

impl<const TREE_HEIGHT: usize, T: Clone> MerkleProverKnowledge<TREE_HEIGHT, T> {
    pub fn new(leaf: impl Borrow<T>, path: impl Borrow<[[T; ARITY]; TREE_HEIGHT]>) -> Self {
        Self {
            leaf: leaf.borrow().clone(),
            path: path.borrow().clone(),
        }
    }
}

impl<const TREE_HEIGHT: usize, F: FieldExt> MerkleProverKnowledge<TREE_HEIGHT, Value<F>> {
    pub fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
    ) -> Result<MerkleProverKnowledge<TREE_HEIGHT, AssignedCell<F>>, Error> {
        let mut layouter = layouter.namespace(|| "MerkleProverKnowledge");
        let [leaf] =
            assign_values_to_advice(&mut layouter, advice_pool, "leaf", [(self.leaf, "leaf")])?;
        let path = layouter.assign_region(
            || "path",
            |region| assign_2d_advice_array(region, self.path, advice_pool.get_array()),
        )?;
        Ok(MerkleProverKnowledge { path, leaf })
    }
}

impl<const TREE_HEIGHT: usize, F: FieldExt> ProverKnowledge<F>
    for MerkleProverKnowledge<TREE_HEIGHT, F>
{
    type Circuit = MerkleCircuit<TREE_HEIGHT, F>;
    type PublicInput = MerkleInstance;

    fn random_correct_example(rng: &mut impl RngCore) -> Self {
        let mut path = [(); TREE_HEIGHT].map(|_| [(); ARITY].map(|_| F::random(&mut *rng)));
        for i in 1..TREE_HEIGHT {
            path[i][0] = hash(&path[i - 1]);
        }
        MerkleProverKnowledge::new(path[0][0], path)
    }

    fn create_circuit(&self) -> MerkleCircuit<TREE_HEIGHT, F> {
        MerkleCircuit(MerkleProverKnowledge {
            leaf: Value::known(self.leaf),
            path: self.path.map(|level| level.map(Value::known)),
        })
    }
}

impl<const TREE_HEIGHT: usize, F: FieldExt> PublicInputProvider<MerkleInstance, F>
    for MerkleProverKnowledge<TREE_HEIGHT, F>
{
    fn compute_public_input(&self, instance_id: MerkleInstance) -> F {
        match instance_id {
            MerkleInstance::MerkleRoot => hash(&self.path[TREE_HEIGHT - 1]),
        }
    }
}
