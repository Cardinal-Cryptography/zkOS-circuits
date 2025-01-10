use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

use halo2_proofs::plonk::{Advice, Column, ColumnType, ConstraintSystem, Fixed};

use crate::F;

#[derive(Clone, Debug)]
pub struct ColumnPool<C: ColumnType> {
    pool: Rc<RefCell<Vec<Column<C>>>>,
    access_counter: Rc<RefCell<Vec<usize>>>,
}

impl<C: ColumnType> ColumnPool<C> {
    /// Create a new empty pool.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            pool: Rc::new(RefCell::new(Vec::new())),
            access_counter: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn add_column(&mut self, column: Column<C>) {
        self.pool.borrow_mut().push(column);
        self.access_counter.borrow_mut().push(0);
    }
}

impl ColumnPool<Advice> {
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

impl ColumnPool<Fixed> {
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

impl<C: ColumnType> ColumnPool<C> {
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
