use alloc::collections::BTreeSet;
use core::borrow::Borrow;

use halo2_proofs::plonk::Error;
use strum::IntoEnumIterator;

pub struct Todo<Task>(BTreeSet<Task>);

impl<Task: IntoEnumIterator + Ord> Default for Todo<Task> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Task: IntoEnumIterator + Ord> Todo<Task> {
    /// Create a new todolist containing all tasks to be done.
    pub fn new() -> Self {
        Self(BTreeSet::from_iter(Task::iter()))
    }

    /// Mark `task` as done. Returns an error if the task was already done.
    pub fn check_off(&mut self, task: impl Borrow<Task>) -> Result<(), Error> {
        match self.0.remove(task.borrow()) {
            true => Ok(()),
            false => Err(Error::Synthesis),
        }
    }

    /// Check if all tasks are done.
    pub fn assert_done(&self) -> Result<(), Error> {
        match self.0.is_empty() {
            true => Ok(()),
            false => Err(Error::ConstraintSystemFailure),
        }
    }
}
