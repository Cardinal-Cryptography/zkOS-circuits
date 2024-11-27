use alloc::{vec, vec::Vec};
use core::cell::Cell;

use halo2_proofs::{
    arithmetic::Field,
    plonk::{Advice, Column, ColumnType, ConstraintSystem, Fixed},
};

#[derive(Clone, Debug)]
pub struct ColumnPool<C: ColumnType> {
    pool: Vec<Column<C>>,
    last_accessed_at: Cell<usize>,
}

impl ColumnPool<Advice> {
    /// Create a new empty advice pool.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            pool: Vec::new(),
            last_accessed_at: Cell::new(0),
        }
    }

    /// Ensure that there are at least `capacity` advice columns in the constraint system `cs`,
    /// registering new ones if necessary. Enable equality for each of them.
    pub fn ensure_capacity<F: Field>(&mut self, cs: &mut ConstraintSystem<F>, capacity: usize) {
        for _ in self.len()..capacity {
            let column = cs.advice_column();
            cs.enable_equality(column);
            self.pool.push(column);
        }
    }
}

impl ColumnPool<Fixed> {
    /// Create a new fixed pool. It will contain 1 column for advice constraining constants.
    pub fn new<F: Field>(cs: &mut ConstraintSystem<F>) -> Self {
        let pool = vec![cs.fixed_column()];
        cs.enable_constant(pool[0]);
        Self {
            pool,
            last_accessed_at: Cell::new(0),
        }
    }

    /// Ensure that there are at least `capacity` fixed columns in the constraint system `cs`,
    /// registering new ones if necessary. This count doesn't include the constant column.
    pub fn ensure_capacity<F: Field>(&mut self, cs: &mut ConstraintSystem<F>, capacity: usize) {
        for i in (self.len() - 1)..capacity {
            let column = cs.fixed_column();
            self.pool.insert(i, column); // keep the constant column at the end
        }
    }
}

impl<C: ColumnType> ColumnPool<C> {
    /// Get some advice column from the pool.
    ///
    /// The index is not guaranteed (some inner load balancing might be applied).
    pub fn get_any(&self) -> Column<C> {
        let next = (self.last_accessed_at.get() + 1) % self.len();
        self.last_accessed_at.set(next);
        self.pool[next]
    }

    /// Get the column at the specified index.
    pub fn get(&self, index: usize) -> Column<C> {
        self.pool[index]
    }

    /// Get the number of columns in the pool.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Get an array of columns from the pool.
    pub fn get_array<const N: usize>(&self) -> [Column<C>; N] {
        self.pool[..N].try_into().unwrap()
    }
}
