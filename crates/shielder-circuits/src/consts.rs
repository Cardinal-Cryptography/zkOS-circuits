pub const MAX_K: u32 = 13;

pub const MAX_NONCE_BIT_LENGTH: usize = 16;
pub const MAX_TOKEN_ACCUMULATION_BIT_LENGTH: usize = 112;
pub const MAX_ACCOUNT_BALANCE_PASSING_RANGE_CHECK: u128 =
    (1u128 << MAX_TOKEN_ACCUMULATION_BIT_LENGTH) - 1u128;

pub const RANGE_PROOF_CHUNK_SIZE: usize = 8;

pub const RANGE_PROOF_NUM_WORDS: usize = 14;
static_assertions::const_assert_eq!(
    MAX_TOKEN_ACCUMULATION_BIT_LENGTH,
    RANGE_PROOF_NUM_WORDS * RANGE_PROOF_CHUNK_SIZE
);

pub const NONCE_RANGE_PROOF_NUM_WORDS: usize = 2;
static_assertions::const_assert_eq!(
    MAX_NONCE_BIT_LENGTH,
    RANGE_PROOF_CHUNK_SIZE * NONCE_RANGE_PROOF_NUM_WORDS
);

pub mod merkle_constants {
    // Merkle tree arity.
    pub const ARITY: usize = 7;
    pub const NOTE_TREE_HEIGHT: usize = 13;
    // Width parameter of the hashing chip. Due to implementation constraints, this must be ARITY + 1.
    pub const WIDTH: usize = 8;
    static_assertions::const_assert_eq!(WIDTH, ARITY + 1);

    pub const TOKEN_TREE_HEIGHT: usize = 5;
}

/// nonces that make up pow-anonymity are drawn randomly from [0...2^MAX_NONCE_BIT_LENGTH]
pub const NONCE_UPPER_LIMIT: u32 = 1 << MAX_NONCE_BIT_LENGTH;
