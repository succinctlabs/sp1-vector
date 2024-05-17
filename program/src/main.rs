//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_consensus::{Signature, VerificationKey};

pub fn main() {
    // NOTE: values of n larger than 186 will overflow the u128 type,
    // resulting in output that doesn't match fibonacci sequence.
    // However, the resulting proof will still be valid!
    let pk = sp1_zkvm::io::read_vec();
    let sig = sp1_zkvm::io::read_vec();

    let vk: VerificationKey = VerificationKey::try_from(pk.as_ref() as &[u8]).unwrap();
    let sig = Signature::try_from(sig.as_ref()).unwrap();

    vk.verify(&sig, &[0u8; 32]).unwrap();
}
