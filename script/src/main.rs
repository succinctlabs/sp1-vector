//! A simple script to generate and verify the proof of a given program.

use std::env;

use ed25519_consensus::{Signature, SigningKey, VerificationKey, VerificationKeyBytes};
use rand::thread_rng;
use sp1_sdk::{ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    let mut stdin = SP1Stdin::new();
    let sk = SigningKey::new(thread_rng());
    let pk = VerificationKey::from(&sk);
    let msg = b"ed25519-consensus test message";

    let sig = sk.sign(&msg[..]);

    let pk_array: [u8; 32] = pk.into();
    let sig_array: [u8; 64] = sig.into();

    stdin.write_vec(pk_array.to_vec());
    stdin.write_vec(sig_array.to_vec());

    env::set_var("SP1_PROVER", "mock");
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
