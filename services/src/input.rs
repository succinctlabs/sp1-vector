use anyhow::Result;
use avail_subxt::primitives::grandpa::{AuthorityId, ConsensusLog};
use sp1_vector_primitives::rotate::get_next_validator_pubkeys_from_epoch_end_header;
use sp1_vector_primitives::types::{
    CircuitJustification, HeaderRangeInputs, HeaderRotateData, Precommit, RotateInputs,
};
use sp1_vector_primitives::{compute_authority_set_commitment, consts::HASH_SIZE};
use sp_core::H256;
use std::cmp::Ordering;
use std::env;
use subxt::backend::rpc::RpcSubscription;

use crate::types::{EncodedFinalityProof, FinalityProof, GrandpaJustification};
use alloy::primitives::{B256, B512};
use avail_subxt::avail_client::AvailClient;
use avail_subxt::config::substrate::DigestItem;
use avail_subxt::primitives::Header;
use avail_subxt::{api, RpcParams};
use codec::{Compact, Decode, Encode};
use futures::future::join_all;
use sp_core::ed25519;

/// In order to avoid errors from the RPC client, tasks should coordinate via this mutex to coordinate
/// large amounts of concurrent requests.
static CONCURRENCY_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// An RPC data fetcher for fetching data for VectorX. The vectorx_query_url is only necessary when
/// querying justifications.
pub struct RpcDataFetcher {
    pub client: AvailClient,
    pub avail_chain_id: String,
    pub vectorx_query_url: Option<String>,
}

/// Data for the header range request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeaderRangeRequestData {
    pub trusted_block: u32,
    pub target_block: u32,
    pub is_target_epoch_end_block: bool,
}

impl RpcDataFetcher {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let url = env::var("AVAIL_URL").expect("AVAIL_URL must be set");
        let client = AvailClient::new(url.as_str()).await.unwrap();
        let avail_chain_id = env::var("AVAIL_CHAIN_ID").expect("AVAIL_CHAIN_ID must be set");
        let vectorx_query_url = env::var("VECTORX_QUERY_URL").ok();
        RpcDataFetcher {
            client,
            avail_chain_id,
            vectorx_query_url,
        }
    }

    /// Gets a justification from the vectorx-query service, which reads the data from the AWS DB.
    /// Returns a parsed GrandpaJustification struct on success.
    /// 
    /// # Arguments
    /// * `block_number` - The block number for which the justification is requested.
    ///
    /// # Errors
    /// Returns an error if:
    /// - VECTORX_QUERY_URL is not set,
    /// - The HTTP request fails,
    /// - The response JSON is missing expected fields,
    /// - The justification cannot be deserialized.
    pub async fn get_justification(&self, block_number: u32) -> Result<GrandpaJustification> {
        // Ensure the vectorx_query_url is set, otherwise return an error.
        let vectorx_query_url = self.vectorx_query_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("VECTORX_QUERY_URL must be set"))?;

        // Construct the base URL for the justification API endpoint.
        let base_justification_query_url = format!("{}/api/justification", vectorx_query_url);

        // Build the full request URL with chain ID and block number as query parameters.
        let request_url = format!(
            "{}?availChainId={}&blockNumber={}",
            base_justification_query_url, self.avail_chain_id, block_number
        );

        // Send a GET request to the justification service.
        let response = reqwest::get(&request_url).await?;
        // Parse the response body as JSON.
        let json_response = response.json::<serde_json::Value>().await?;

        // Safely check the "success" field in the response.
        // If missing or not a boolean, return an error.
        let is_success = json_response.get("success")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'success' field in justification response"))?;
        // If the request was not successful, extract the error message or use a default one.
        if !is_success {
            let error_msg = json_response.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("No justification found for the specified block number.");
            return Err(anyhow::anyhow!(error_msg));
        }

        // Safely extract the justification string from the response.
        // The expected structure is: { "justification": { "S": "<json string>" } }
        let justification_str = json_response
            .get("justification")
            .and_then(|j| j.get("S"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow::anyhow!("Justification field missing or not a string"))?;

        // Deserialize the justification string into a GrandpaJustification struct.
        let justification_data: GrandpaJustification =
            serde_json::from_str(justification_str)
                .map_err(|e| anyhow::anyhow!("Couldn't deserialize justification: {}", e))?;

        Ok(justification_data)
    }

    /// Get the inputs for a header range proof. Optionally pass in the header range commitment tree size.
    /// If not passed in, it will be set to the nearest power of 2.
    pub async fn get_header_range_inputs(
        &self,
        header_range_request_data: HeaderRangeRequestData,
        header_range_commitment_tree_size: Option<u32>,
    ) -> HeaderRangeInputs {
        let num_headers =
            header_range_request_data.target_block - header_range_request_data.trusted_block + 1;
        let merkle_tree_size: usize;
        if let Some(header_range_commitment_tree_size) = header_range_commitment_tree_size {
            assert!(
                header_range_commitment_tree_size >= num_headers
                    && header_range_commitment_tree_size.is_power_of_two(),
                "Header range commitment tree size must be greater than or equal to the number of headers and a power of two"
            );
            merkle_tree_size = header_range_commitment_tree_size as usize;
        } else {
            // NOTE: DANGEROUS. ONLY USED IN TESTING. IN PROD, FETCH FROM CONTRACT.
            merkle_tree_size = get_merkle_tree_size(num_headers);
        }

        tracing::debug!(
            "Getting block headers range from {} to {}",
            header_range_request_data.trusted_block,
            header_range_request_data.target_block
        );

        let headers = self
            .get_block_headers_range(
                header_range_request_data.trusted_block,
                header_range_request_data.target_block,
            )
            .await;
        let encoded_headers: Vec<Vec<u8>> = headers.iter().map(|header| header.encode()).collect();

        let target_justification = self
            .get_justification_data_for_block(
                header_range_request_data.target_block,
                header_range_request_data.is_target_epoch_end_block,
            )
            .await
            .expect("Failed to get justification data for target block.");

        HeaderRangeInputs {
            merkle_tree_size,
            encoded_headers,
            target_justification,
        }
    }

    pub async fn get_rotate_inputs(&self, authority_set_id: u64) -> RotateInputs {
        let justification = self
            .get_justification_data_epoch_end_block(authority_set_id)
            .await;

        let header_rotate_data = self.get_header_rotate(authority_set_id).await;

        RotateInputs {
            justification,
            header_rotate_data,
        }
    }

    // This function returns the last block justified by target_authority_set_id. This block
    // also specifies the new authority set, which starts justifying after this block.
    // Returns 0 if curr_authority_set_id <= target_authority_set_id.
    pub async fn last_justified_block(&self, target_authority_set_id: u64) -> u32 {
        let mut low = 0;
        let head_block = self.get_head().await;
        let mut high = head_block.number;
        let mut epoch_end_block_number = 0;

        while low <= high {
            let mid = (low + high) / 2;
            let mid_authority_set_id = self.get_authority_set_id(mid).await;

            match mid_authority_set_id.cmp(&(target_authority_set_id + 1)) {
                Ordering::Equal => {
                    if mid == 0 {
                        // Special case: there is no block "mid - 1", just return the found block.
                        epoch_end_block_number = mid;
                        break;
                    }
                    let prev_authority_set_id = self.get_authority_set_id(mid - 1).await;
                    if prev_authority_set_id == target_authority_set_id {
                        epoch_end_block_number = mid;
                        break;
                    } else {
                        high = mid - 1;
                    }
                }
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid - 1,
            }
        }
        epoch_end_block_number
    }

    pub async fn get_block_hash(&self, block_number: u32) -> B256 {
        let block_hash = self
            .client
            .legacy_rpc()
            .chain_get_block_hash(Some(block_number.into()))
            .await;

        B256::from(block_hash.unwrap().unwrap().0)
    }

    /// This function returns a vector of headers for a given range of block numbers, inclusive of the start and end block numbers.
    pub async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        // Fetch the headers in batches of MAX_CONCURRENT_WS_REQUESTS. The WS connection will error if there
        // are too many concurrent requests with Rpc(ClientError(MaxSlotsExceeded)).
        const MAX_CONCURRENT_WS_REQUESTS: usize = 200;

        // Take the guard to coordinate concurrent requests.
        let _guard = CONCURRENCY_MUTEX.lock().await;

        let mut headers = Vec::new();
        let mut curr_block = start_block_number;
        while curr_block <= end_block_number {
            let end_block = std::cmp::min(
                curr_block + MAX_CONCURRENT_WS_REQUESTS as u32 - 1,
                end_block_number,
            );
            let header_futures: Vec<_> = (curr_block..end_block + 1)
                .map(|block_number| self.get_header(block_number))
                .collect();

            // Await all futures concurrently
            let headers_batch: Vec<Header> = join_all(header_futures).await;

            headers.extend_from_slice(&headers_batch);
            curr_block += MAX_CONCURRENT_WS_REQUESTS as u32;
        }
        headers
    }

    pub async fn get_header(&self, block_number: u32) -> Header {
        let block_hash = self.get_block_hash(block_number).await;
        let header_result = self
            .client
            .legacy_rpc()
            .chain_get_header(Some(H256::from(block_hash.0)))
            .await;
        header_result.unwrap().unwrap()
    }

    pub async fn get_head(&self) -> Header {
        let head_block_hash = self
            .client
            .legacy_rpc()
            .chain_get_finalized_head()
            .await
            .unwrap();
        let header = self
            .client
            .legacy_rpc()
            .chain_get_header(Some(head_block_hash))
            .await;
        header.unwrap().unwrap()
    }

    pub async fn get_authority_set_id(&self, block_number: u32) -> u64 {
        let block_hash = self.get_block_hash(block_number).await;

        let set_id_key = api::storage().grandpa().current_set_id();
        self.client
            .storage()
            .at(H256::from(block_hash.0))
            .fetch(&set_id_key)
            .await
            .unwrap()
            .unwrap()
    }

    // This function returns the authorities (as AffinePoint and public key bytes) for a given block number
    // by fetching the "authorities_bytes" from storage and decoding the bytes to a VersionedAuthorityList.
    // Note: The authorities returned by this function attest to block_number + 1.
    pub async fn get_authorities(&self, block_number: u32) -> Vec<B256> {
        let block_hash = self.get_block_hash(block_number).await;

        let grandpa_authorities = self
            .client
            .runtime_api()
            .at(H256::from(block_hash.0))
            .call_raw::<Vec<(ed25519::Public, u64)>>("GrandpaApi_grandpa_authorities", None)
            .await
            .unwrap();

        let mut authorities: Vec<B256> = Vec::new();
        for (pub_key, weight) in grandpa_authorities {
            authorities.push(B256::from(pub_key.0));
            let expected_weight = 1;
            // Assert the LE representation of the weight of each validator is 1.
            assert_eq!(
                weight, expected_weight,
                "The weight of the authority is not 1!"
            );
        }

        authorities
    }

    /// Gets the authority set id and authority set hash that are defined in block_number. This authority set
    /// attests to block_number + 1.
    pub async fn get_authority_set_data_for_block(&self, block_number: u32) -> (u64, B256) {
        let authority_set_id = self.get_authority_set_id(block_number).await;
        let authority_set_hash = self
            .compute_authority_set_hash_for_block(block_number)
            .await;
        (authority_set_id, authority_set_hash)
    }

    /// Computes the authority_set_hash for a given block number. Note: This is the authority set hash
    /// that validates the next block after the given block number.
    pub async fn compute_authority_set_hash_for_block(&self, block_number: u32) -> B256 {
        let authorities = self.get_authorities(block_number).await;
        compute_authority_set_commitment(authorities.as_slice())
    }

    /// Get the justification data necessary for the circuit using GrandpaJustification and the block number.
    async fn compute_data_from_justification(
        &self,
        justification: GrandpaJustification,
        block_number: u32,
    ) -> CircuitJustification {
        // Get the authority set id that attested to block_number.
        let authority_set_id = self.get_authority_set_id(block_number - 1).await;

        // Get the authority set for the block number.
        let authorities = self.get_authorities(block_number - 1).await;

        convert_justification_and_valset_to_circuit(justification, authorities, authority_set_id)
    }

    /// Get the justification for a block using the DB cache from the justification indexer.
    pub async fn get_justification_data_for_block(
        &self,
        block_number: u32,
        is_epoch_end_block: bool,
    ) -> Option<CircuitJustification> {
        let grandpa_justification = match is_epoch_end_block {
            true => {
                self.get_justification_data_for_block_unsafe(block_number)
                    .await
            }
            false => self.get_justification(block_number).await,
        };

        if grandpa_justification.is_err() {
            return None;
        }
        let grandpa_justification = grandpa_justification.unwrap();

        // Convert DB stored justification into CircuitJustification.
        let circuit_justification = self
            .compute_data_from_justification(grandpa_justification, block_number)
            .await;
        Some(circuit_justification)
    }

    /// Get the latest justification data. Because Avail does not store the justification data for
    /// all blocks, we can only generate a proof using the latest justification data or the justification data for a specific block.
    pub async fn get_latest_justification_data(&self) -> (CircuitJustification, Header) {
        let sub: Result<RpcSubscription<GrandpaJustification>, _> = self
            .client
            .rpc()
            .subscribe(
                "grandpa_subscribeJustifications",
                RpcParams::new(),
                "grandpa_unsubscribeJustifications",
            )
            .await;
        let mut sub = sub.unwrap();

        // Wait for new justification.
        if let Some(Ok(justification)) = sub.next().await {
            // Get the header corresponding to the new justification.
            let header = self
                .client
                .legacy_rpc()
                .chain_get_header(Some(justification.commit.target_hash))
                .await
                .unwrap()
                .unwrap();
            let block_number = header.number;
            return (
                self.compute_data_from_justification(justification, block_number)
                    .await,
                header,
            );
        }
        panic!("No justification found")
    }

    /// Get the justification data for a block number. Unsafe, not guaranteed to be correct.
    pub async fn get_justification_data_for_block_unsafe(
        &self,
        epoch_end_block: u32,
    ) -> Result<GrandpaJustification> {
        // If epoch end block, use grandpa_proveFinality to get the justification.
        let mut params = RpcParams::new();
        let _ = params.push(epoch_end_block);

        let encoded_finality_proof = self
            .client
            .rpc()
            .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
            .await
            .unwrap();

        let finality_proof: FinalityProof =
            Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
        let justification: GrandpaJustification =
            Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

        Ok(justification)
    }

    /// Get the justification data for an epoch end block from the curr_authority_set_id to the next authority set id.
    /// Fetch the authority set and justification proof for the last block in the current epoch. If the finality proof is a
    /// simple justification, return a CircuitJustification with the encoded precommit that all
    /// authorities sign, the validator signatures, and the authority set's pubkeys.
    pub async fn get_justification_data_epoch_end_block(
        &self,
        curr_authority_set_id: u64,
    ) -> CircuitJustification {
        let epoch_end_block = self.last_justified_block(curr_authority_set_id).await;
        if epoch_end_block == 0 {
            panic!("Current authority set is still active!");
        }

        let grandpa_justification = self
            .get_justification_data_for_block_unsafe(epoch_end_block)
            .await
            .expect("No justification found");
        self.compute_data_from_justification(grandpa_justification, epoch_end_block)
            .await
    }

    /// Filter the authority set changes from the header at the end of the epoch associated with the
    /// given authority set id.
    /// Source: https://github.com/Rahul8869/avail-light/blob/1ee54e10c037474d2ee99a0762e6ffee43f0df1c/src/utils.rs#L78
    pub async fn filter_auth_set_changes(
        &self,
        authority_set_id: u64,
    ) -> Vec<Vec<(AuthorityId, u64)>> {
        let epoch_end_block = self.last_justified_block(authority_set_id).await;
        if epoch_end_block == 0 {
            panic!("Current authority set is still active!");
        }

        let header = self.get_header(epoch_end_block).await;

        let new_auths = header
            .digest
            .logs
            .iter()
            .filter_map(|e| match &e {
                avail_subxt::config::substrate::DigestItem::Consensus(
                    [b'F', b'R', b'N', b'K'],
                    data,
                ) => match ConsensusLog::<u32>::decode(&mut data.as_slice()) {
                    Ok(ConsensusLog::ScheduledChange(x)) => Some(x.next_authorities),
                    Ok(ConsensusLog::ForcedChange(_, x)) => Some(x.next_authorities),
                    _ => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        new_auths
    }

    /// This function takes in a block_number as input, and fetches the new authority set specified
    /// in the epoch end block. It returns the data necessary to prove the new authority set, which
    /// specifies the new authority set hash, the number of authorities, and the start and end
    /// position of the encoded new authority set in the header.
    pub async fn get_header_rotate(&self, authority_set_id: u64) -> HeaderRotateData {
        let epoch_end_block = self.last_justified_block(authority_set_id).await;
        if epoch_end_block == 0 {
            panic!("Current authority set is still active!");
        }

        let header = self.get_header(epoch_end_block).await;

        let header_bytes = header.encode();

        // Fetch the new authority set specified in the epoch end block.
        let expected_new_authorities = self.get_authorities(epoch_end_block).await;

        let mut position = 0;
        let number_encoded = Compact(epoch_end_block).encode();
        // Skip past parent_hash, number, state_root, extrinsics_root.
        position += HASH_SIZE + number_encoded.len() + HASH_SIZE + HASH_SIZE;
        let mut found_correct_log = false;
        for log in header.digest.logs {
            let encoded_log = log.clone().encode();
            // Note: Two bytes are skipped between the consensus id and value.
            if let DigestItem::Consensus(consensus_id, value) = log {
                if consensus_id == [70, 82, 78, 75] {
                    // Decode the consensus log. Only if this is the correct log, will we continue.
                    match ConsensusLog::<u32>::decode(&mut value.as_slice()) {
                        Ok(ConsensusLog::ScheduledChange(_)) => {
                            println!("Found ScheduledChange log!");
                            found_correct_log = true;
                        }
                        Ok(ConsensusLog::ForcedChange(_, _)) => {
                            println!("Found ForcedChange log!");
                            found_correct_log = true;
                        }
                        _ => {
                            position += encoded_log.len();
                            continue;
                        }
                    }
                    break;
                }
            }
            // If this is not the correct log, increment position by the length of the encoded log.
            if !found_correct_log {
                position += encoded_log.len();
            }
        }

        // Panic if there is not a consensus log.
        if !found_correct_log {
            panic!(
                "Block: {:?} should be an epoch end block, but did not find corresponding consensus log!",
                epoch_end_block
            );
        }

        let extracted_new_authorities =
            get_next_validator_pubkeys_from_epoch_end_header(&header_bytes, position);

        assert_eq!(extracted_new_authorities, expected_new_authorities);

        HeaderRotateData {
            header_bytes,
            consensus_log_position: position,
        }
    }
}

/// Converts GrandpaJustification and validator set to CircuitJustification.
pub fn convert_justification_and_valset_to_circuit(
    justification: GrandpaJustification,
    validator_set: Vec<B256>,
    set_id: u64,
) -> CircuitJustification {
    let precommits = justification
        .commit
        .precommits
        .iter()
        .map(|e| Precommit {
            target_number: e.precommit.target_number,
            target_hash: B256::from(e.precommit.target_hash.0),
            pubkey: B256::from(e.id.0),
            signature: B512::from(e.signature.0),
        })
        .collect::<Vec<_>>();

    let ancestries_encoded = justification
        .votes_ancestries
        .iter()
        .map(Encode::encode)
        .collect::<Vec<_>>();

    CircuitJustification {
        round: justification.round,
        authority_set_id: set_id,
        valset_pubkeys: validator_set.clone(),
        precommits,
        block_hash: justification.commit.target_hash.0.into(),
        ancestries_encoded,
    }
}

/// NOTE: ONLY USED IN TESTING. IN PROD, FETCH FROM CONTRACT.
fn get_merkle_tree_size(num_headers: u32) -> usize {
    let mut size = 1;
    while size < num_headers {
        size *= 2;
    }
    size as usize
}

#[cfg(test)]
mod tests {
    use crate::types::{Commit, Precommit, SignerMessage};
    use avail_subxt::config::Header;
    use avail_subxt::primitives::Header as DaHeader;
    use ed25519::Public;
    use serde::{Deserialize, Serialize};
    use sp1_vector_primitives::{
        rotate::get_next_validator_pubkeys_from_epoch_end_header, verify_justification,
    };
    use std::fs::File;
    use test_case::test_case;

    use super::*;

    #[tokio::test]
    async fn test_get_simple_justification_change_authority_set() {
        let fetcher = RpcDataFetcher::new().await;

        // This is an block in the middle of an era.
        let block = 645570;

        let authority_set_id = fetcher.get_authority_set_id(block - 1).await;
        let authority_set_hash = fetcher
            .compute_authority_set_hash_for_block(block - 1)
            .await;
        let header = fetcher.get_header(block).await;
        let header_hash = header.hash();

        println!("authority_set_id {:?}", authority_set_id);
        println!("authority_set_hash {:?}", hex::encode(authority_set_hash.0));
        println!("header_hash {:?}", hex::encode(header_hash.0));

        let _ = fetcher
            .get_justification_data_epoch_end_block(authority_set_id)
            .await;
    }

    #[tokio::test]
    async fn test_get_new_authority_set() {
        dotenv::dotenv().ok();
        env_logger::init();

        let fetcher = RpcDataFetcher::new().await;

        // A binary search given a target_authority_set_id, returns the last block justified by
        // target_authority_set_id. This block also specifies the new authority set,
        // target_authority_set_id + 1.
        let target_authority_set_id = 2;
        let epoch_end_block_number = fetcher.last_justified_block(target_authority_set_id).await;

        // Verify that this is an epoch end block.
        assert_ne!(epoch_end_block_number, 0);
        println!("epoch_end_block_number {:?}", epoch_end_block_number);

        let previous_authority_set_id = fetcher
            .get_authority_set_id(epoch_end_block_number - 1)
            .await;
        let new_authority_set_id = fetcher.get_authority_set_id(epoch_end_block_number).await;

        let new_authorities = fetcher.get_authorities(epoch_end_block_number).await;
        let expected_new_authority_set_hash = compute_authority_set_commitment(&new_authorities);

        // Verify this is an epoch end block.
        assert_eq!(previous_authority_set_id + 1, new_authority_set_id);
        assert_eq!(previous_authority_set_id, target_authority_set_id);

        let rotate_data = fetcher.get_header_rotate(new_authority_set_id).await;
        let new_authority_set_hash =
            compute_authority_set_commitment(&get_next_validator_pubkeys_from_epoch_end_header(
                &rotate_data.header_bytes,
                rotate_data.consensus_log_position,
            ));
        assert_eq!(new_authority_set_hash, expected_new_authority_set_hash);
    }

    #[test]
    fn test_signed_message_encoding() {
        let h1 = H256::random();

        // Cannonical way of forming the signed message (taken from Substrate code)
        let msg1 = Encode::encode(&(
            &SignerMessage::PrecommitMessage(Precommit {
                target_hash: h1,
                target_number: 2,
            }),
            3u64,
            4u64,
        ));

        // Simplified encoding using none of the Substrate-specific structures
        let msg2 = Encode::encode(&(1u8, B256::from(h1.0).0, 2u32, 3u64, 4u64));
        assert_eq!(msg1, msg2, "Messages are not equal")
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct JsonGrandpaJustification {
        pub round: u64,
        pub commit: Commit,
        pub votes_ancestries: Vec<DaHeader>,
    }

    impl From<GrandpaJustification> for JsonGrandpaJustification {
        fn from(value: GrandpaJustification) -> Self {
            Self {
                round: value.round,
                commit: value.commit,
                votes_ancestries: value.votes_ancestries,
            }
        }
    }

    impl From<JsonGrandpaJustification> for GrandpaJustification {
        fn from(value: JsonGrandpaJustification) -> Self {
            GrandpaJustification {
                round: value.round,
                commit: value.commit,
                votes_ancestries: value.votes_ancestries,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ValidatorSet {
        pub set_id: u64,
        pub validator_set: Vec<Public>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ValidatorSetAndJustification {
        pub validator_set: ValidatorSet,
        pub justification: JsonGrandpaJustification,
    }

    #[test_case("test_assets/ancestry.json"; "Complex ancestry")]
    #[test_case("test_assets/ancestry_missing_link_no_majority.json" => panics "Less than 2/3 of signatures are verified"; "Missing ancestor negative case")]
    #[test_case("test_assets/ancestry_missing_link_works.json"; "Missing ancestor")]
    /// Tesing some complex justifications, serialized in JSON format (for readability)
    fn test_complex_justification(path: &str) {
        let test_case_file = File::open(path).unwrap();
        let validator_set_and_justification: ValidatorSetAndJustification =
            serde_json::from_reader(test_case_file).unwrap();

        let justification: GrandpaJustification =
            validator_set_and_justification.justification.into();
        let validator_set = validator_set_and_justification
            .validator_set
            .validator_set
            .iter()
            .map(|e| B256::from(e.0))
            .collect::<Vec<_>>();
        let circuit_justification = convert_justification_and_valset_to_circuit(
            justification,
            validator_set,
            validator_set_and_justification.validator_set.set_id,
        );

        verify_justification(&circuit_justification)
    }
}
