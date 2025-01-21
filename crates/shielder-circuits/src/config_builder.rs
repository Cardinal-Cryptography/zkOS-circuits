use halo2_proofs::plonk::{Advice, ConstraintSystem, Fixed};

use crate::{
    chips::{
        balances_increase::BalancesIncreaseChip,
        range_check::RangeCheckChip,
        sum::SumChip,
        token_index::{self, TokenIndexChip, TokenIndexInstance},
    },
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
    F,
};

pub struct ConfigsBuilder<'cs> {
    system: &'cs mut ConstraintSystem<F>,
    advice_pool: ColumnPool<Advice>,
    fixed_pool: ColumnPool<Fixed>,

    balances_increase: Option<BalancesIncreaseChip>,
    merkle: Option<MerkleChip>,
    poseidon: Option<PoseidonChip>,
    range_check: Option<RangeCheckChip>,
    sum: Option<SumChip>,
    token_index: Option<TokenIndexChip>,
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
            advice_pool: ColumnPool::<Advice>::new(),
            fixed_pool: ColumnPool::<Fixed>::new(),

            balances_increase: None,
            merkle: None,
            poseidon: None,
            range_check: None,
            sum: None,
            token_index: None,
        }
    }

    pub fn advice_pool(&self) -> ColumnPool<Advice> {
        self.advice_pool.clone()
    }

    pub fn with_balances_increase(mut self) -> Self {
        check_if_cached!(self, balances_increase);

        let advice_pool = self.advice_pool_with_capacity(4).clone();
        let gate_advice = advice_pool.get_array::<{ balance_increase::NUM_ADVICE_COLUMNS }>();

        self.balances_increase = Some(BalancesIncreaseChip {
            gate: BalanceIncreaseGate::create_gate(
                self.system,
                BalanceIncreaseGateAdvices {
                    balance_old: gate_advice[0],
                    increase_value: gate_advice[1],
                    token_indicator: gate_advice[2],
                    balance_new: gate_advice[3],
                },
            ),
            advice_pool,
        });
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

        let advice_pool = self.advice_pool_with_capacity(ARITY + 1).clone();

        let needle = advice_pool.get(ARITY);
        let advice_path = advice_pool.get_array::<ARITY>();

        self.merkle = Some(MerkleChip {
            membership_gate: MembershipGate::create_gate(self.system, (needle, advice_path)),
            advice_pool,
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
        self.advice_pool.ensure_capacity(system, 1);
        let advice_pool = self.advice_pool.clone();

        self.range_check = Some(RangeCheckChip::new(
            system,
            advice_pool.clone(),
            self.sum.clone().unwrap(),
        ));
        self
    }

    pub fn range_check_chip(&self) -> RangeCheckChip {
        self.range_check.clone().expect("RangeCheck not configured")
    }

    pub fn with_sum(mut self) -> Self {
        check_if_cached!(self, sum);

        let advice_pool = self.advice_pool_with_capacity(3).clone();
        self.sum = Some(SumChip {
            gate: SumGate::create_gate(self.system, advice_pool.get_array()),
            advice: advice_pool.get_any(),
        });
        self
    }

    pub fn sum_chip(&self) -> SumChip {
        self.sum.clone().expect("Sum not configured")
    }

    pub fn with_token_index(mut self, public_inputs: InstanceWrapper<TokenIndexInstance>) -> Self {
        check_if_cached!(self, token_index);

        let advice_pool = self
            .advice_pool_with_capacity(token_index::gates::NUM_INDEX_GATE_COLUMNS)
            .clone();

        self.token_index = Some(TokenIndexChip::new(self.system, advice_pool, public_inputs));
        self
    }

    pub fn token_index_chip(&self) -> TokenIndexChip {
        self.token_index.clone().expect("TokenIndex not configured")
    }

    fn advice_pool_with_capacity(&mut self, capacity: usize) -> &ColumnPool<Advice> {
        self.advice_pool.ensure_capacity(self.system, capacity);
        &self.advice_pool
    }

    fn fixed_pool_with_capacity(&mut self, capacity: usize) -> &ColumnPool<Fixed> {
        self.fixed_pool.ensure_capacity(self.system, capacity);
        &self.fixed_pool
    }
}
