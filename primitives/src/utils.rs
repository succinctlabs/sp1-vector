use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sp_core::H256;

/// This function is useful for verifying that a Ed25519 signature is valid, it will panic if the signature is not valid
pub fn verify_signature(pubkey_bytes: &[u8; 32], signed_message: &[u8], signature: &[u8; 64]) {
    let pubkey = VerifyingKey::from_bytes(pubkey_bytes).unwrap();
    let verified = pubkey.verify(signed_message, &Signature::from_bytes(signature));
    if verified.is_err() {
        panic!("Signature is not valid");
    }
}

// Compute the chained hash of the authority set.
pub fn compute_authority_set_hash(authorities: &[&[u8]]) -> Vec<u8> {
    let mut hash_so_far = Vec::new();
    for i in 0..authorities.len() {
        let authority = authorities[i];
        let mut hasher = sha2::Sha256::new();
        hasher.update(hash_so_far);
        hasher.update(authority);
        hash_so_far = hasher.finalize().to_vec();
    }
    hash_so_far
}

pub fn decode_precommit(precommit: Vec<u8>) -> (H256, u32, u64, u64) {
    // The first byte should be a 1.
    assert_eq!(precommit[0], 1);

    // The next 32 bytes are the block hash.
    let block_hash = &precommit[1..33];

    // The next 4 bytes are the block number.
    let block_number = &precommit[33..37];
    // Convert the block number to a u32.
    let block_number = u32::from_le_bytes(block_number.try_into().unwrap());

    // The next 8 bytes are the justification round.
    let round = &precommit[37..45];
    // Convert the round to a u64.
    let round = u64::from_le_bytes(round.try_into().unwrap());

    // The next 8 bytes are the authority set id.
    let authority_set_id = &precommit[45..53];
    // Convert the authority set id to a u64.
    let authority_set_id = u64::from_le_bytes(authority_set_id.try_into().unwrap());

    (
        H256::from_slice(block_hash),
        block_number,
        round,
        authority_set_id,
    )
}
