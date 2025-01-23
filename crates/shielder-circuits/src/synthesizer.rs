use alloc::string::String;

use halo2_proofs::{
    circuit::{Cell, Layouter, Region, Table, Value},
    plonk::{Advice, Challenge, Column, Error, Instance},
};

use crate::{
    column_pool::{AccessColumn, ColumnPool, PreSynthesisPhase, SynthesisPhase},
    Fr,
};

pub struct Synthesizer<L: Layouter<Fr>> {
    layouter: L,
    advice_pool: ColumnPool<Advice, SynthesisPhase>,
}

impl<L: Layouter<Fr>> Synthesizer<L> {
    pub fn new(layouter: L, advice_pool: ColumnPool<Advice, PreSynthesisPhase>) -> Self {
        Self {
            layouter,
            advice_pool: advice_pool.start_synthesis(),
        }
    }
}

/// Delegate `Layouter` implementation to the inner layouter.
impl<L: Layouter<Fr>> Layouter<Fr> for Synthesizer<L> {
    type Root = L::Root;

    fn assign_region<A, AR, N, NR>(&mut self, name: N, assignment: A) -> Result<AR, Error>
    where
        A: FnMut(Region<'_, Fr>) -> Result<AR, Error>,
        N: Fn() -> NR,
        NR: Into<String>,
    {
        self.layouter.assign_region(name, assignment)
    }

    fn assign_table<A, N, NR>(&mut self, name: N, assignment: A) -> Result<(), Error>
    where
        A: FnMut(Table<'_, Fr>) -> Result<(), Error>,
        N: Fn() -> NR,
        NR: Into<String>,
    {
        self.layouter.assign_table(name, assignment)
    }

    fn constrain_instance(
        &mut self,
        cell: Cell,
        column: Column<Instance>,
        row: usize,
    ) -> Result<(), Error> {
        self.layouter.constrain_instance(cell, column, row)
    }

    fn get_challenge(&self, challenge: Challenge) -> Value<Fr> {
        self.layouter.get_challenge(challenge)
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self.layouter.get_root()
    }

    fn push_namespace<NR: Into<String>, N: FnOnce() -> NR>(&mut self, name_fn: N) {
        self.layouter.push_namespace(name_fn)
    }

    fn pop_namespace(&mut self, gadget_name: Option<String>) {
        self.layouter.pop_namespace(gadget_name)
    }
}

/// Delegate `AccessColumn` implementation to the inner advice pool.
impl<L: Layouter<Fr>> AccessColumn<Advice> for Synthesizer<L> {
    fn get_any(&self) -> Column<Advice> {
        self.advice_pool.get_any()
    }

    fn get(&self, index: usize) -> Column<Advice> {
        self.advice_pool.get(index)
    }

    fn get_array<const N: usize>(&self) -> [Column<Advice>; N] {
        self.advice_pool.get_array()
    }
}
