use super::{Shortlist, CHUNK_SIZE};
use crate::{poseidon::off_circuit::hash, Field, Fr};

pub fn shortlist_hash<const N: usize>(shortlist: &Shortlist<Fr, N>) -> Fr {
    let mut last = Fr::zero();
    let mut input = [Fr::zero(); CHUNK_SIZE + 1];
    let items = &shortlist.items[..];

    for (i, chunk) in items.chunks(CHUNK_SIZE).enumerate().rev() {
        // While the tail is all zeros, we skip hashing.
        if i > 0 && chunk.iter().all(Fr::is_zero_vartime) && last.is_zero_vartime() {
            continue;
        }
        input[CHUNK_SIZE] = last;
        input[0..CHUNK_SIZE].copy_from_slice(chunk);
        last = hash(&input);
    }

    last
}

#[cfg(test)]
mod tests {
    use std::array;

    use crate::{
        chips::shortlist_hash::{off_circuit::shortlist_hash, Shortlist},
        poseidon::off_circuit::hash,
        Fr,
    };

    #[test]
    fn test_single_chunk_hash() {
        let input: Shortlist<Fr, 6> = Shortlist::new(array::from_fn(|i| (i as u64).into()));

        let expected_hash = hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::zero(),
        ]);

        assert_eq!(expected_hash, shortlist_hash(&input));
    }

    #[test]
    fn test_chained_hash() {
        let input: Shortlist<Fr, 12> = Shortlist::new(array::from_fn(|i| (i as u64).into()));

        let hash_chunk_2 = hash(&[
            Fr::from(6),
            Fr::from(7),
            Fr::from(8),
            Fr::from(9),
            Fr::from(10),
            Fr::from(11),
            Fr::from(0),
        ]);
        let expected_hash = hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            hash_chunk_2,
        ]);

        assert_eq!(expected_hash, shortlist_hash(&input));
    }

    #[test]
    fn empty_first_chunk_is_hashed() {
        let input: Shortlist<Fr, 6> = Shortlist::default();
        let expected_hash = hash(&[Fr::zero(); 7]);
        assert_eq!(expected_hash, shortlist_hash(&input));
    }

    fn empty_tail_is_skipped<const N: usize>() {
        let input: Shortlist<Fr, N> = Shortlist::new(array::from_fn(|i| {
            if i >= 6 {
                Fr::zero()
            } else {
                (i as u64).into()
            }
        }));
        let expected_hash = hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::zero(),
        ]);
        assert_eq!(expected_hash, shortlist_hash(&input));
    }

    #[test]
    fn empty_tails_are_skipped() {
        empty_tail_is_skipped::<6>();
        empty_tail_is_skipped::<12>();
        empty_tail_is_skipped::<18>();
    }

    #[test]
    fn empty_middle_chunk_is_not_skipped() {
        let input: Shortlist<Fr, 18> = Shortlist::new(array::from_fn(|i| {
            if i >= 6 && i < 12 {
                Fr::zero()
            } else {
                (i as u64).into()
            }
        }));
        let hash_chunk_3 = hash(&[
            Fr::from(12),
            Fr::from(13),
            Fr::from(14),
            Fr::from(15),
            Fr::from(16),
            Fr::from(17),
            Fr::from(0),
        ]);
        let hash_chunk_2 = hash(&[
            Fr::from(0),
            Fr::from(0),
            Fr::from(0),
            Fr::from(0),
            Fr::from(0),
            Fr::from(0),
            Fr::from(hash_chunk_3),
        ]);
        let expected_hash = hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::from(hash_chunk_2),
        ]);

        assert_eq!(expected_hash, shortlist_hash(&input));
    }
}
