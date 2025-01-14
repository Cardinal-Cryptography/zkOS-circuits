use halo2_proofs::plonk::{Advice, ConstraintSystem, Fixed};

use crate::{
    chips::{balances_increase::BalancesIncreaseChip, range_check::RangeCheckChip, sum::SumChip},
    column_pool::ColumnPool,
    consts::merkle_constants::{ARITY, WIDTH},
    gates::{
        balance_increase::{self, BalanceIncreaseGate, BalanceIncreaseGateAdvices},
        membership::MembershipGate,
        sum::SumGate,
        Gate,
    },
    instance_wrapper::InstanceWrapper,
    merkle::{MerkleChip, MerkleInstance},
    poseidon::{circuit::PoseidonChip, spec::PoseidonSpec},
    FieldExt,
};

pub struct Empty;
pub struct With<T>(T);

type WithBalancesIncrease = With<BalancesIncreaseChip>;
type WithSum = With<SumChip>;
type WithMerkle<F> = With<MerkleChip<F>>;
type WithPoseidon<F> = With<PoseidonChip<F>>;
type WithRangeCheck = With<RangeCheckChip>;

pub struct ConfigsBuilder<'cs, F: FieldExt, Poseidon, Merkle, BalancesIncrease, Sum, RangeCheck> {
    base_builder: BaseBuilder<'cs, F>,
    poseidon: Poseidon,
    merkle: Merkle,
    balances_increase: BalancesIncrease,
    sum: Sum,
    range_check: RangeCheck,
}

impl<'cs, F: FieldExt> ConfigsBuilder<'cs, F, Empty, Empty, Empty, Empty, Empty> {
    pub fn new(system: &'cs mut ConstraintSystem<F>) -> Self {
        Self {
            base_builder: BaseBuilder::new(system),
            poseidon: Empty,
            merkle: Empty,
            balances_increase: Empty,
            sum: Empty,
            range_check: Empty,
        }
    }
}

impl<'cs, F: FieldExt> ConfigsBuilder<'cs, F, Empty, Empty, Empty, Empty, Empty> {
    pub fn balances_increase(
        mut self,
    ) -> ConfigsBuilder<'cs, F, Empty, Empty, WithBalancesIncrease, Empty, Empty> {
        let advice_pool = self.base_builder.advice_pool_with_capacity(4).clone();
        let gate_advice = advice_pool.get_array::<{ balance_increase::NUM_ADVICE_COLUMNS }>();
        let system = &mut self.base_builder.system;

        let balances_increase = BalancesIncreaseChip {
            gate: BalanceIncreaseGate::create_gate(
                system,
                BalanceIncreaseGateAdvices {
                    balance_old: gate_advice[0],
                    increase_value: gate_advice[1],
                    token_indicator: gate_advice[2],
                    balance_new: gate_advice[3],
                },
            ),
            advice_pool,
        };

        ConfigsBuilder {
            base_builder: self.base_builder,
            poseidon: self.poseidon,
            merkle: self.merkle,
            balances_increase: With(balances_increase),
            sum: self.sum,
            range_check: self.range_check,
        }
    }
}

impl<'cs, F: FieldExt, Poseidon, BalancesIncrease>
    ConfigsBuilder<'cs, F, Poseidon, Empty, BalancesIncrease, Empty, Empty>
{
    pub fn sum(
        mut self,
    ) -> ConfigsBuilder<'cs, F, Poseidon, Empty, BalancesIncrease, WithSum, Empty> {
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
            balances_increase: self.balances_increase,
            sum: With(sum),
            range_check: self.range_check,
        }
    }
}

impl<'cs, F: FieldExt, BalancesIncrease, Sum>
    ConfigsBuilder<'cs, F, Empty, Empty, BalancesIncrease, Sum, Empty>
{
    pub fn poseidon(
        mut self,
    ) -> ConfigsBuilder<'cs, F, WithPoseidon<F>, Empty, BalancesIncrease, Sum, Empty> {
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
            balances_increase: self.balances_increase,
            sum: self.sum,
            range_check: self.range_check,
        }
    }
}

impl<'cs, F: FieldExt, BalancesIncrease, Sum>
    ConfigsBuilder<'cs, F, WithPoseidon<F>, Empty, BalancesIncrease, Sum, Empty>
{
    pub fn merkle(
        mut self,
        public_inputs: InstanceWrapper<MerkleInstance>,
    ) -> ConfigsBuilder<'cs, F, WithPoseidon<F>, WithMerkle<F>, BalancesIncrease, Sum, Empty> {
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
            balances_increase: self.balances_increase,
            sum: self.sum,
            range_check: self.range_check,
        }
    }
}

impl<'cs, F: FieldExt, Poseidon, Merkle, BalancesIncrease, RangeCheck>
    ConfigsBuilder<'cs, F, Poseidon, Merkle, BalancesIncrease, WithSum, RangeCheck>
{
    pub fn range_check(
        mut self,
    ) -> ConfigsBuilder<'cs, F, Poseidon, Merkle, BalancesIncrease, WithSum, WithRangeCheck> {
        let system = &mut self.base_builder.system;
        self.base_builder.advice_pool.ensure_capacity(system, 1);
        let advice_pool = self.base_builder.advice_pool.clone();

        let range_check = RangeCheckChip::new(system, advice_pool.clone(), self.sum.0.clone());

        ConfigsBuilder {
            base_builder: self.base_builder,
            poseidon: self.poseidon,
            merkle: self.merkle,
            balances_increase: self.balances_increase,
            sum: self.sum,
            range_check: With(range_check),
        }
    }
}

impl<'cs, F: FieldExt, Poseidon, Merkle, BalancesIncrease, Sum>
    ConfigsBuilder<'cs, F, Poseidon, Merkle, BalancesIncrease, Sum, WithRangeCheck>
{
    pub fn resolve_range_check(&self) -> RangeCheckChip {
        self.range_check.0.clone()
    }
}

impl<'cs, F: FieldExt, Merkle, BalancesIncrease, Sum, RangeCheck>
    ConfigsBuilder<'cs, F, WithPoseidon<F>, Merkle, BalancesIncrease, Sum, RangeCheck>
{
    pub fn resolve_poseidon(&self) -> (ColumnPool<Advice>, PoseidonChip<F>) {
        (
            self.base_builder.advice_pool.clone(),
            self.poseidon.0.clone(),
        )
    }
}

impl<'cs, F: FieldExt, BalancesIncrease, Sum, RangeCheck>
    ConfigsBuilder<'cs, F, WithPoseidon<F>, WithMerkle<F>, BalancesIncrease, Sum, RangeCheck>
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
    ConfigsBuilder<'cs, F, Poseidon, Merkle, WithBalancesIncrease, WithSum, RangeCheck>
{
    pub fn resolve_balances_increase_chip(&self) -> (ColumnPool<Advice>, BalancesIncreaseChip) {
        (
            self.base_builder.advice_pool.clone(),
            self.balances_increase.0.clone(),
        )
    }
}

impl<'cs, F: FieldExt, Poseidon, Merkle, BalancesIncrease, RangeCheck>
    ConfigsBuilder<'cs, F, Poseidon, Merkle, BalancesIncrease, WithSum, RangeCheck>
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
