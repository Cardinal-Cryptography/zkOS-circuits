use alloc::collections::BTreeSet;

use halo2_proofs::plonk::{Advice, Column};

// Checks if given advice columns are unique, panics with custom `msg` if they are not.
pub fn expect_unique_columns(columns: &[Column<Advice>], msg: &str) {
    let set = BTreeSet::from_iter(columns.iter().map(|column| column.index()));
    assert_eq!(set.len(), columns.len(), "{}", msg);
}
