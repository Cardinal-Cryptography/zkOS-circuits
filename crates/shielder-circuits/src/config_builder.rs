use halo2_proofs::plonk::{Advice, ConstraintSystem, Fixed};

use crate::{
    chips::{range_check::RangeCheckChip, sum::SumChip},
    column_pool::ColumnPool,
    consts::merkle_constants::{ARITY, WIDTH},
    gates::{membership::MembershipGate, range_check::RangeCheckGate, sum::SumGate, Gate},
    instance_wrapper::InstanceWrapper,
    merkle::{MerkleChip, MerkleInstance},
    poseidon::{circuit::PoseidonChip, spec::PoseidonSpec},
    FieldExt,
};

pub struct Empty;
pub struct With<T>(T);

type WithSum = With<SumChip>;
type WithMerkle<F> = With<MerkleChip<F>>;
type WithPoseidon<F> = With<PoseidonChip<F>>;
type WithRangeCheck<const CHUNK_SIZE: usize> = With<RangeCheckChip<{ CHUNK_SIZE }>>;

pub struct ConfigsBuilder<'cs, F: FieldExt, Poseidon, Merkle, Sum, RangeCheck> {
    base_builder: BaseBuilder<'cs, F>,
    poseidon: Poseidon,
    merkle: Merkle,
    sum: Sum,
    range_check: RangeCheck,
}

impl<'cs, F: FieldExt> ConfigsBuilder<'cs, F, Empty, Empty, Empty, Empty> {
    pub fn new(system: &'cs mut ConstraintSystem<F>) -> Self {
        Self {
            base_builder: BaseBuilder::new(system),
            poseidon: Empty,
            merkle: Empty,
            sum: Empty,
            range_check: Empty,
        }
    }
}

impl<'cs, F: FieldExt, Poseidon> ConfigsBuilder<'cs, F, Poseidon, Empty, Empty, Empty> {
    pub fn sum(mut self) -> ConfigsBuilder<'cs, F, Poseidon, Empty, WithSum, Empty> {
        let advice_pool = self.base_builder.advice_pool_with_capacity(3);
        let gate_advice = advice_pool.get_array();
        let advice = advice_pool.get_any();
        let system = &mut self.base_builder.system;

        let sum = SumChip {
            gate: SumGate::create_gate(system, gate_advice),
            advice,
        };

        ConfigsBuilder {
            base_builder: self.base_builder,
            poseidon: self.poseidon,
            merkle: self.merkle,
            sum: With(sum),
            range_check: self.range_check,
        }
    }
}

impl<'cs, F: FieldExt, Sum> ConfigsBuilder<'cs, F, Empty, Empty, Sum, Empty> {
    pub fn poseidon(mut self) -> ConfigsBuilder<'cs, F, WithPoseidon<F>, Empty, Sum, Empty> {
        let advice_pool = self.base_builder.advice_pool_with_capacity(WIDTH + 1);
        let advice_array = advice_pool.get_array::<WIDTH>();
        let advice = advice_pool.get(WIDTH);

        let fixed_pool = self.base_builder.fixed_pool_with_capacity(WIDTH);
        let fixed_array = fixed_pool.get_array::<WIDTH>();

        let poseidon_config = PoseidonChip::configure::<PoseidonSpec>(
            self.base_builder.system,
            advice_array,
            fixed_array,
            advice,
        );
        let poseidon = PoseidonChip::construct(poseidon_config);

        ConfigsBuilder {
            base_builder: self.base_builder,
            poseidon: With(poseidon),
            merkle: self.merkle,
            sum: self.sum,
            range_check: self.range_check,
        }
    }
}

impl<'cs, F: FieldExt, Sum> ConfigsBuilder<'cs, F, WithPoseidon<F>, Empty, Sum, Empty> {
    pub fn merkle(
        mut self,
        public_inputs: InstanceWrapper<MerkleInstance>,
    ) -> ConfigsBuilder<'cs, F, WithPoseidon<F>, WithMerkle<F>, Sum, Empty> {
        let advice_pool = self
            .base_builder
            .advice_pool_with_capacity(ARITY + 1)
            .clone();

        let needle = advice_pool.get(ARITY);
        let advice_path = advice_pool.get_array::<ARITY>();

        let system = &mut self.base_builder.system;
        let merkle = MerkleChip::<F> {
            membership_gate: MembershipGate::create_gate(system, (needle, advice_path)),
            advice_pool,
            public_inputs,
            poseidon: self.poseidon.0.clone(),
        };

        ConfigsBuilder {
            base_builder: self.base_builder,
            poseidon: self.poseidon,
            merkle: With(merkle),
            sum: self.sum,
            range_check: self.range_check,
        }
    }
}

impl<'cs, F: FieldExt, Poseidon, Merkle, RangeCheck>
    ConfigsBuilder<'cs, F, Poseidon, Merkle, WithSum, RangeCheck>
{
    pub fn range_check<const CHUNK_SIZE: usize>(
        mut self,
    ) -> ConfigsBuilder<'cs, F, Poseidon, Merkle, WithSum, WithRangeCheck<CHUNK_SIZE>> {
        let advice = self.base_builder.advice_pool_with_capacity(1).get_any();
        let advice_pool = self.base_builder.advice_pool.clone();
        let system = &mut self.base_builder.system;

        let gate = RangeCheckGate::<CHUNK_SIZE>::create_gate(system, advice);
        let range_check = RangeCheckChip {
            range_gate: gate,
            sum_chip: self.sum.0.clone(),
            advice_pool,
        };

        ConfigsBuilder {
            base_builder: self.base_builder,
            poseidon: self.poseidon,
            merkle: self.merkle,
            sum: self.sum,
            range_check: With(range_check),
        }
    }
}

impl<'cs, F: FieldExt, Poseidon, Merkle, Sum, const CHUNK_SIZE: usize>
    ConfigsBuilder<'cs, F, Poseidon, Merkle, Sum, WithRangeCheck<CHUNK_SIZE>>
{
    pub fn resolve_range_check(&self) -> RangeCheckChip<CHUNK_SIZE> {
        self.range_check.0.clone()
    }
}

impl<'cs, F: FieldExt, Merkle, Sum, RangeCheck>
    ConfigsBuilder<'cs, F, WithPoseidon<F>, Merkle, Sum, RangeCheck>
{
    pub fn resolve_poseidon(&self) -> (ColumnPool<Advice>, PoseidonChip<F>) {
        (
            self.base_builder.advice_pool.clone(),
            self.poseidon.0.clone(),
        )
    }
}

impl<'cs, F: FieldExt, Sum, RangeCheck>
    ConfigsBuilder<'cs, F, WithPoseidon<F>, WithMerkle<F>, Sum, RangeCheck>
{
    pub fn resolve_merkle(&self) -> (ColumnPool<Advice>, PoseidonChip<F>, MerkleChip<F>) {
        (
            self.base_builder.advice_pool.clone(),
            self.poseidon.0.clone(),
            self.merkle.0.clone(),
        )
    }
}

impl<'cs, F: FieldExt, Poseidon, Merkle, RangeCheck>
    ConfigsBuilder<'cs, F, Poseidon, Merkle, WithSum, RangeCheck>
{
    pub fn resolve_sum_chip(&self) -> (ColumnPool<Advice>, SumChip) {
        (self.base_builder.advice_pool.clone(), self.sum.0.clone())
    }
}

struct BaseBuilder<'cs, F: FieldExt> {
    system: &'cs mut ConstraintSystem<F>,
    advice_pool: ColumnPool<Advice>,
    fixed_pool: ColumnPool<Fixed>,
}

impl<'cs, F: FieldExt> BaseBuilder<'cs, F> {
    pub fn new(system: &'cs mut ConstraintSystem<F>) -> Self {
        Self {
            advice_pool: ColumnPool::<Advice>::new(),
            fixed_pool: ColumnPool::<Fixed>::new(),
            system,
        }
    }

    pub fn advice_pool_with_capacity(&mut self, capacity: usize) -> &ColumnPool<Advice> {
        self.advice_pool.ensure_capacity(self.system, capacity);
        &self.advice_pool
    }

    pub fn fixed_pool_with_capacity(&mut self, capacity: usize) -> &ColumnPool<Fixed> {
        self.fixed_pool.ensure_capacity(self.system, capacity);
        &self.fixed_pool
    }
}
