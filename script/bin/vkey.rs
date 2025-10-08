use sp1_sdk::{HashableKey, MockProver, Prover, ProvingKey};
use sp1_vectorx_script::SP1_VECTOR_ELF;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = MockProver::new().await;
    let pk = client
        .setup(sp1_sdk::Elf::Static(SP1_VECTOR_ELF))
        .await
        .expect("Failed to setup prover");
    let vk = pk.verifying_key().clone();

    println!("VK: {}", vk.bytes32());

    Ok(())
}
