use super::{Shortlist, CHUNK_SIZE};
use crate::{poseidon::off_circuit::hash, Fr};

pub fn shortlist_hash<const N: usize>(shortlist: &Shortlist<Fr, N>) -> Fr {
    let mut last = Fr::zero();
    let mut input = [Fr::zero(); CHUNK_SIZE + 1];
    let items = &shortlist.items[..];

    for chunk in items.chunks(CHUNK_SIZE).rev() {
        let size = input.len() - 1;
        input[size] = last;
        input[0..size].copy_from_slice(chunk);
        last = hash(&input);
    }

    last
}

#[cfg(test)]
mod tests {
    use std::array;

    use crate::{
        chips::shortlist_hash::{off_circuit, Shortlist},
        poseidon, Fr,
    };

    #[test]
    fn test_chained_hash() {
        let input: Shortlist<Fr, 12> = Shortlist::new(array::from_fn(|i| (i as u64).into()));

        let hash_chunk_2 = poseidon::off_circuit::hash(&[
            Fr::from(6),
            Fr::from(7),
            Fr::from(8),
            Fr::from(9),
            Fr::from(10),
            Fr::from(11),
            Fr::from(0),
        ]);
        let expected_hash = crate::poseidon::off_circuit::hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            hash_chunk_2,
        ]);

        assert2::assert!(expected_hash == off_circuit::shortlist_hash(&input));
    }

    #[test]
    fn test_single_chunk_hash() {
        let input: Shortlist<Fr, 6> = Shortlist::new(array::from_fn(|i| (i as u64).into()));

        let expected_hash = crate::poseidon::off_circuit::hash(&[
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::zero(),
        ]);

        assert2::assert!(expected_hash == off_circuit::shortlist_hash(&input));
    }
}
