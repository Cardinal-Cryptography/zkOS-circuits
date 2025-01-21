use halo2_proofs::plonk::{Advice, ConstraintSystem, Fixed};

use crate::{
    chips::{balances_increase::BalancesIncreaseChip, range_check::RangeCheckChip, sum::SumChip},
    column_pool::{ColumnPool, ConfigPhase, SynthesisPhase},
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
    F,
};

pub struct ConfigsBuilder<'cs> {
    system: &'cs mut ConstraintSystem<F>,
    advice_pool: ColumnPool<Advice, ConfigPhase>,
    fixed_pool: ColumnPool<Fixed, ConfigPhase>,

    balances_increase: Option<BalancesIncreaseChip>,
    merkle: Option<MerkleChip>,
    poseidon: Option<PoseidonChip>,
    range_check: Option<RangeCheckChip>,
    sum: Option<SumChip>,
}

macro_rules! check_if_cached {
    ($self:ident, $field:ident) => {
        if $self.$field.is_some() {
            return $self;
        }
    };
}

impl<'cs> ConfigsBuilder<'cs> {
    pub fn new(system: &'cs mut ConstraintSystem<F>) -> Self {
        Self {
            system,
            advice_pool: ColumnPool::<Advice, _>::new(),
            fixed_pool: ColumnPool::<Fixed, _>::new(),

            balances_increase: None,
            merkle: None,
            poseidon: None,
            range_check: None,
            sum: None,
        }
    }

    pub fn finish(self) -> ColumnPool<Advice, SynthesisPhase> {
        self.advice_pool.conclude_configuration()
    }

    pub fn with_balances_increase(mut self) -> Self {
        check_if_cached!(self, balances_increase);

        let advice_pool = self.advice_pool_with_capacity(4);
        let gate_advice = advice_pool.get_array::<{ balance_increase::NUM_ADVICE_COLUMNS }>();

        self.balances_increase = Some(BalancesIncreaseChip::new(BalanceIncreaseGate::create_gate(
            self.system,
            BalanceIncreaseGateAdvices {
                balance_old: gate_advice[0],
                increase_value: gate_advice[1],
                token_indicator: gate_advice[2],
                balance_new: gate_advice[3],
            },
        )));
        self
    }

    pub fn balances_increase_chip(&self) -> BalancesIncreaseChip {
        self.balances_increase
            .clone()
            .expect("BalancesIncrease not configured")
    }

    pub fn with_poseidon(mut self) -> Self {
        check_if_cached!(self, poseidon);

        let advice_pool = self.advice_pool_with_capacity(WIDTH + 1);
        let advice_array = advice_pool.get_array::<WIDTH>();
        let advice = advice_pool.get(WIDTH);

        let fixed_pool = self.fixed_pool_with_capacity(WIDTH);
        let fixed_array = fixed_pool.get_array::<WIDTH>();

        let poseidon_config =
            PoseidonChip::configure::<PoseidonSpec>(self.system, advice_array, fixed_array, advice);

        self.poseidon = Some(PoseidonChip::construct(poseidon_config));
        self
    }

    pub fn poseidon_chip(&self) -> PoseidonChip {
        self.poseidon.clone().expect("Poseidon not configured")
    }

    pub fn with_merkle(mut self, public_inputs: InstanceWrapper<MerkleInstance>) -> Self {
        check_if_cached!(self, merkle);
        self = self.with_poseidon();

        let advice_pool = self.advice_pool_with_capacity(ARITY + 1);
        let needle = advice_pool.get(ARITY);
        let advice_path = advice_pool.get_array::<ARITY>();

        self.merkle = Some(MerkleChip {
            membership_gate: MembershipGate::create_gate(self.system, (needle, advice_path)),
            public_inputs,
            poseidon: self.poseidon_chip(),
        });
        self
    }

    pub fn merkle_chip(&self) -> MerkleChip {
        self.merkle.clone().expect("Merkle not configured")
    }

    pub fn with_range_check(mut self) -> Self {
        check_if_cached!(self, range_check);
        self = self.with_sum();

        let system = &mut self.system;
        self.range_check = Some(RangeCheckChip::new(
            system,
            &mut self.advice_pool,
            self.sum.clone().unwrap(),
        ));
        self
    }

    pub fn range_check_chip(&self) -> RangeCheckChip {
        self.range_check.clone().expect("RangeCheck not configured")
    }

    pub fn with_sum(mut self) -> Self {
        check_if_cached!(self, sum);
        let advice = self.advice_pool_with_capacity(3).get_array();
        self.sum = Some(SumChip::new(SumGate::create_gate(self.system, advice)));
        self
    }

    pub fn sum_chip(&self) -> SumChip {
        self.sum.clone().expect("Sum not configured")
    }

    fn advice_pool_with_capacity(&mut self, capacity: usize) -> &ColumnPool<Advice, ConfigPhase> {
        self.advice_pool.ensure_capacity(self.system, capacity);
        &self.advice_pool
    }

    fn fixed_pool_with_capacity(&mut self, capacity: usize) -> &ColumnPool<Fixed, ConfigPhase> {
        self.fixed_pool.ensure_capacity(self.system, capacity);
        &self.fixed_pool
    }
}
