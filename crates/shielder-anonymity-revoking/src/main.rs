use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use shielder_circuits::poseidon::off_circuit::padded_hash;

fn find_id(id_hiding: Fr) {
    let file = File::open("ids.csv").unwrap();
    let reader = BufReader::new(file);
    for id in reader.lines() {
        println!("Checking id {:?}", id);
        let id = id.unwrap();
        let id = Fr::from_str_vartime(&id).unwrap();
        let salt = is_hashed_id(id_hiding, id);
        if let Some(salt) = salt {
            println!("id {:?} id_hiding {:?} salt {:?} ", id, id_hiding, salt);
            return;
        }
    }
    println!("id for id_hiding {:?} not found", id_hiding);
}

fn is_hashed_id(id_hiding: Fr, id: Fr) -> Option<Fr> {
    let mut salt = Fr::zero();
    for _ in 0..65536 {
        let hash = padded_hash(&[id, salt]);

        if hash == id_hiding {
            return Some(salt);
        }

        salt += Fr::one();
    }
    None
}

fn main() {
    let file = File::open("transactions.csv").unwrap();
    let reader = BufReader::new(file);

    for id_hiding in reader.lines() {
        let id_hiding = id_hiding.unwrap();
        let id_hiding = Fr::from_str_vartime(&id_hiding).unwrap();
        find_id(id_hiding);
    }
}
