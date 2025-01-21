use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

use halo2_proofs::plonk::{Advice, Column, ColumnType, ConstraintSystem, Fixed};

use crate::F;

pub enum ConfigPhase {}
pub enum SynthesisPhase {}

#[derive(Debug)]
pub struct ColumnPool<C: ColumnType, Phase> {
    pool: Rc<RefCell<Vec<Column<C>>>>,
    access_counter: Rc<RefCell<Vec<usize>>>,
}

impl<C: ColumnType> ColumnPool<C, ConfigPhase> {
    /// Create a new empty pool.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            pool: Default::default(),
            access_counter: Default::default(),
        }
    }

    pub fn conclude_configuration(self) -> ColumnPool<Advice, SynthesisPhase> {
        ColumnPool {
            pool: self.pool,
            access_counter: self.access_counter,
        }
    }

    fn add_column(&mut self, column: Column<C>) {
        self.pool.borrow_mut().push(column);
        self.access_counter.borrow_mut().push(0);
    }
}

impl ColumnPool<Advice, ConfigPhase> {
    /// Ensure that there are at least `capacity` advice columns in the constraint system `cs`,
    /// registering new ones if necessary. Enable equality for each of them.
    pub fn ensure_capacity(&mut self, cs: &mut ConstraintSystem<F>, capacity: usize) {
        for _ in self.len()..capacity {
            let column = cs.advice_column();
            cs.enable_equality(column);
            self.add_column(column);
        }
    }
}

impl ColumnPool<Fixed, ConfigPhase> {
    /// Ensure that there are at least `capacity` fixed columns in the constraint system `cs`,
    /// registering new ones if necessary. Enable storing constants in each of them.
    pub fn ensure_capacity(&mut self, cs: &mut ConstraintSystem<F>, capacity: usize) {
        for _ in self.len()..capacity {
            let column = cs.fixed_column();
            cs.enable_constant(column);
            self.add_column(column);
        }
    }
}

impl<C: ColumnType, Phase> ColumnPool<C, Phase> {
    /// Get some advice column from the pool.
    ///
    /// The index is not guaranteed (some inner load balancing might be applied).
    pub fn get_any(&self) -> Column<C> {
        let idx = self
            .access_counter
            .borrow()
            .iter()
            .enumerate()
            .min_by_key(|&(_, count)| count)
            .map(|(idx, _)| idx)
            .expect("empty pool");
        self.get(idx)
    }

    /// Get the column at the specified index.
    pub fn get(&self, index: usize) -> Column<C> {
        self.access_counter.borrow_mut()[index] += 1;
        self.pool.borrow()[index]
    }

    /// Get the number of columns in the pool.
    pub fn len(&self) -> usize {
        self.pool.borrow().len()
    }

    /// Get an array of columns from the pool.
    pub fn get_array<const N: usize>(&self) -> [Column<C>; N] {
        for i in 0..N {
            self.access_counter.borrow_mut()[i] += 1;
        }
        self.pool.borrow()[..N].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::plonk::{Advice, ConstraintSystem};

    use crate::{column_pool::ColumnPool, F};

    #[test]
    fn cloned_pools_share_new_columns() {
        let mut cs = ConstraintSystem::<F>::default();
        let mut root_pool = ColumnPool::<Advice>::new();

        // 1. Create some shared column in the root pool.
        root_pool.ensure_capacity(&mut cs, 1);

        // 2. Clone the root pool.
        let mut cloned_pool = root_pool.clone();

        // 3. Ensure 2 columns in both pools.
        root_pool.ensure_capacity(&mut cs, 2);
        cloned_pool.ensure_capacity(&mut cs, 2);

        // 4. Check that the columns are the same.
        assert_eq!(2, cs.num_advice_columns());
    }

    #[test]
    fn clones_see_new_columns() {
        let mut cs = ConstraintSystem::<F>::default();
        let mut root_pool = ColumnPool::<Advice>::new();

        // 1. Clone the root pool.
        let cloned_pool = root_pool.clone();

        // 2. Ensure 2 columns in the root pool.
        root_pool.ensure_capacity(&mut cs, 2);

        // 3. Check that the clone sees both columns.
        assert_eq!(2, cloned_pool.len());
    }
}
