use halo2_proofs::plonk::{Advice, ConstraintSystem, Fixed};

use crate::{
    chips::{
        balances_increase::BalancesIncreaseChip,
        note::NoteChip,
        point_double::PointDoubleChip,
        points_add::PointsAddChip,
        range_check::RangeCheckChip,
        shortlist_hash::ShortlistHashChip,
        sum::SumChip,
        token_index::{TokenIndexChip, TokenIndexInstance},
    },
    column_pool::{AccessColumn, ColumnPool, ConfigPhase, PreSynthesisPhase},
    consts::{
        merkle_constants::{ARITY, WIDTH},
        NUM_TOKENS,
    },
    gates::{
        balance_increase::{self, BalanceIncreaseGate, BalanceIncreaseGateAdvices},
        membership::MembershipGate,
        point_double::PointDoubleGate,
        points_add::PointsAddGate,
        sum::SumGate,
        Gate,
    },
    instance_wrapper::InstanceWrapper,
    merkle::{MerkleChip, MerkleInstance},
    poseidon::{circuit::PoseidonChip, spec::PoseidonSpec},
    Fr,
};

pub struct ConfigsBuilder<'cs> {
    system: &'cs mut ConstraintSystem<Fr>,
    advice_pool: ColumnPool<Advice, ConfigPhase>,
    fixed_pool: ColumnPool<Fixed, ConfigPhase>,

    balances_increase: Option<BalancesIncreaseChip>,
    merkle: Option<MerkleChip>,
    poseidon: Option<PoseidonChip>,
    range_check: Option<RangeCheckChip>,
    sum: Option<SumChip>,
    points_add: Option<PointsAddChip>,
    point_double: Option<PointDoubleChip>,
    token_index: Option<TokenIndexChip>,
    shortlist_hash: Option<ShortlistHashChip<{ NUM_TOKENS }>>,
    note: Option<NoteChip>,
}

macro_rules! check_if_cached {
    ($self:ident, $field:ident) => {
        if $self.$field.is_some() {
            return $self;
        }
    };
}

impl<'cs> ConfigsBuilder<'cs> {
    pub fn new(system: &'cs mut ConstraintSystem<Fr>) -> Self {
        Self {
            system,
            advice_pool: ColumnPool::<Advice, _>::new(),
            fixed_pool: ColumnPool::<Fixed, _>::new(),

            balances_increase: None,
            merkle: None,
            poseidon: None,
            range_check: None,
            sum: None,
            points_add: None,
            point_double: None,
            token_index: None,
            shortlist_hash: None,
            note: None,
        }
    }

    pub fn finish(self) -> ColumnPool<Advice, PreSynthesisPhase> {
        self.advice_pool.conclude_configuration()
    }

    pub fn with_balances_increase(mut self) -> Self {
        check_if_cached!(self, balances_increase);

        let advice_pool = self.advice_pool_with_capacity(4);
        let gate_advice =
            advice_pool.get_column_array::<{ balance_increase::NUM_ADVICE_COLUMNS }>();

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
        let advice_array = advice_pool.get_column_array::<WIDTH>();
        let advice = advice_pool.get_column(WIDTH);

        let fixed_pool = self.fixed_pool_with_capacity(WIDTH);
        let fixed_array = fixed_pool.get_column_array::<WIDTH>();

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
        let needle = advice_pool.get_column(ARITY);
        let advice_path = advice_pool.get_column_array::<ARITY>();

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
        let advice = self.advice_pool_with_capacity(3).get_column_array();
        self.sum = Some(SumChip::new(SumGate::create_gate(self.system, advice)));
        self
    }

    pub fn sum_chip(&self) -> SumChip {
        self.sum.clone().expect("Sum not configured")
    }

    pub fn with_points_add_chip(mut self) -> Self {
        check_if_cached!(self, points_add);

        let advice_pool = self.advice_pool_with_capacity(9);

        let p = [
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
        ];
        let q = [
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
        ];
        let s = [
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
        ];

        self.points_add = Some(PointsAddChip {
            gate: PointsAddGate::create_gate(self.system, (p, q, s)),
        });
        self
    }

    pub fn points_add_chip(&self) -> PointsAddChip {
        self.points_add
            .clone()
            .expect("PointAddChip not configured")
    }

    pub fn with_point_double_chip(mut self) -> Self {
        check_if_cached!(self, points_add);

        let advice_pool = self.advice_pool_with_capacity(6);

        let p = [
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
        ];
        let s = [
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
            advice_pool.get_any_column(),
        ];

        self.point_double = Some(PointDoubleChip {
            gate: PointDoubleGate::create_gate(self.system, (p, s)),
        });
        self
    }

    pub fn point_double_chip(&self) -> PointDoubleChip {
        self.point_double
            .clone()
            .expect("PointDoubleChip not configured")
    }

    pub fn with_token_index(mut self, public_inputs: InstanceWrapper<TokenIndexInstance>) -> Self {
        check_if_cached!(self, token_index);

        self.token_index = Some(TokenIndexChip::new(
            self.system,
            &mut self.advice_pool,
            public_inputs,
        ));
        self
    }

    pub fn token_index_chip(&self) -> TokenIndexChip {
        self.token_index.clone().expect("TokenIndex not configured")
    }

    pub fn with_shortlist_hash(mut self) -> Self {
        check_if_cached!(self, shortlist_hash);
        self = self.with_poseidon();

        self.shortlist_hash = Some(ShortlistHashChip::new(self.poseidon_chip()));
        self
    }

    pub fn shortlist_hash_chip(&self) -> ShortlistHashChip<NUM_TOKENS> {
        self.shortlist_hash
            .clone()
            .expect("ShortlistHash not configured")
    }

    pub fn with_note(mut self) -> Self {
        check_if_cached!(self, note);
        self = self.with_poseidon();
        self = self.with_shortlist_hash();

        self.note = Some(NoteChip::new(
            self.poseidon_chip(),
            self.shortlist_hash_chip(),
        ));
        self
    }

    pub fn note_chip(&self) -> NoteChip {
        self.note.clone().expect("Note not configured")
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
