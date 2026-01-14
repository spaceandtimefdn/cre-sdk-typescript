use super::hex::{
    deserialize_bytes_hex, deserialize_bytes_hex32, deserialize_bytes32_array_as_hex,
    serialize_bytes_hex, serialize_bytes32_array_as_hex,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::all)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CommitmentScheme {
    Ipa = 0,
    DynamicDory = 1,
    HyperKzg = 2,
}
/// The table commitments with the merkle proof of the commitments
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TableCommitmentWithProof {
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex"
    )]
    pub commitment: Vec<u8>,
    pub merkle_proof: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumSignature {
    /// The `r` component of the signature.
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex32"
    )]
    pub r: [u8; 32],
    /// The `s` component of the signature.
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex32"
    )]
    pub s: [u8; 32],
    /// The recovery ID, usually 27 or 28 for Ethereum.
    pub v: u8,
}

impl EthereumSignature {
    /// Creates a new `EthereumSignature`.
    ///
    /// If the recovery ID (`v`) is not provided, it defaults to `28`.
    pub fn new(r: [u8; 32], s: [u8; 32], v: Option<u8>) -> Self {
        Self {
            r,
            s,
            v: v.unwrap_or(28),
        }
    }
}

/// Represents attestations stored on-chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attestation {
    /// An Ethereum-style attestation.
    #[serde(rename_all = "camelCase")]
    EthereumAttestation {
        /// The signature.
        signature: EthereumSignature,
        /// The public key used to sign the attestation.
        #[serde(
            serialize_with = "serialize_bytes_hex",
            deserialize_with = "deserialize_bytes_hex"
        )]
        proposed_pub_key: Vec<u8>,
        /// The ethereum address for this public key
        #[serde(
            serialize_with = "serialize_bytes_hex",
            deserialize_with = "deserialize_bytes_hex"
        )]
        address20: Vec<u8>,
        /// The state root included in the attestation.
        #[serde(
            serialize_with = "serialize_bytes_hex",
            deserialize_with = "deserialize_bytes_hex"
        )]
        state_root: Vec<u8>,
        /// The block number that was attested
        block_number: u64,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationsResponse {
    /// The attestations for the `attestations_for` block.
    pub attestations: Vec<Attestation>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestedCommitments {
    pub commitments: IndexMap<String, TableCommitmentWithProof>,
    /// The `r` component of the signature.
    #[serde(
        serialize_with = "serialize_bytes32_array_as_hex",
        deserialize_with = "deserialize_bytes32_array_as_hex"
    )]
    pub r: Vec<[u8; 32]>,
    /// The `s` component of the signature.
    #[serde(
        serialize_with = "serialize_bytes32_array_as_hex",
        deserialize_with = "deserialize_bytes32_array_as_hex"
    )]
    pub s: Vec<[u8; 32]>,
    pub v: Vec<u8>,
    pub block_number: u64,
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex32"
    )]
    pub block_hash: [u8; 32],
}

/// The results of the query
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QueryResultsResponse {
    /// The job number corresponding to the initial query
    pub query_id: uuid::Uuid,
    pub created: String,
    /// The commitment scheme used for the query
    pub commitment_scheme: CommitmentScheme,
    pub commitments: AttestedCommitments,
    pub success: bool,
    pub canceled: bool,
    pub error: Option<String>,
    pub completed: String,
    /// The proof plan bytes
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex"
    )]
    pub plan: Vec<u8>,
    /// The proof bytes
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex"
    )]
    pub proof: Vec<u8>,
    /// The result bytes
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex"
    )]
    pub results: Vec<u8>,
}
