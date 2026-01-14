use super::zk_query_models::{Attestation, EthereumSignature, TableCommitmentWithProof};

use super::verifiable_commitment::generate_commitment_leaf;
use eth_merkle_tree::utils::{errors::BytesError, keccak::keccak256, verify::verify_proof};
use indexmap::IndexMap;
use itertools::{Itertools, process_results};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256, Keccak256Core, digest::core_api::CoreWrapper};
use snafu::{ResultExt, Snafu};

/// Top-level error type for the attestation module.
#[derive(Debug, Snafu)]
pub enum AttestationError {
    /// Error during verification.
    #[snafu(display("Verification error: {:?}", source))]
    VerificationError {
        /// Source of the error.
        source: AttestationVerificationError,
    },
    /// Error related to signing or verifying signatures.
    #[snafu(display("Signature error: {:?}", source))]
    SignatureError {
        /// Source of the error.
        source: SignatureError,
    },
    /// Error parsing the public key.
    #[snafu(display("Public key parsing error"))]
    PublicKeyError,
}

/// Specialized `Result` type for the attestation module.
type Result<T, E = AttestationError> = core::result::Result<T, E>;

/// Errors that can occur during verification.
#[derive(Debug, Snafu)]
pub enum AttestationVerificationError {
    /// The recovery ID does not match the Ethereum specification.
    #[snafu(display("Invalid recovery ID: {:?}", recovery_id))]
    InvalidRecoveryIdError {
        /// The recovery id that caused the error
        recovery_id: u8,
    },
    /// The public key could not be recovered.
    #[snafu(display("Key recovery error"))]
    KeyRecoveryError,
    /// The public key could not be parsed.
    #[snafu(display("Public key parsing error"))]
    PublicKeyParsingError,
    /// The signature could not be recovered.
    #[snafu(display("Signature recovery error"))]
    SignatureRecoveryError,

    /// Invalid public key recovered
    #[snafu(display("The signature recovery resulted in an incorrect public key"))]
    InvalidPublicKeyRecovered,
    /// Error related to internals of Merkle tree-related computations.
    #[snafu(display("Bytes error: {:?}", source))]
    BytesError { source: BytesError },
    /// Failure to verify Merkle proof for commitments.
    #[snafu(display("Failed to verify Merkle proof"))]
    FailureToVerifyMerkleProof,
}

impl From<BytesError> for AttestationError {
    fn from(source: BytesError) -> Self {
        AttestationError::VerificationError {
            source: AttestationVerificationError::BytesError { source },
        }
    }
}

impl From<AttestationVerificationError> for AttestationError {
    fn from(source: AttestationVerificationError) -> Self {
        AttestationError::VerificationError { source }
    }
}

/// Errors related to signature generation and validation.
#[derive(Debug, Snafu)]
pub enum SignatureError {
    /// Error parsing the private key into the correct format.
    #[snafu(display("Error creating signing key from private key"))]
    CreateSigningKeyError,
}

fn from_hex(hex: &String) -> Vec<u8> {
    hex::decode(hex.strip_prefix("0x").unwrap()).unwrap()
}

pub fn verify_eth_signature(msg: &[u8], scalars: &EthereumSignature, pub_key: &[u8]) -> Result<()> {
    let signature = Signature::from_scalars(scalars.r, scalars.s)
        .map_err(|_| AttestationVerificationError::SignatureRecoveryError)
        .context(VerificationSnafu)?;

    let recovery_id = RecoveryId::try_from(scalars.v)
        .map_err(|_| AttestationVerificationError::InvalidRecoveryIdError {
            recovery_id: scalars.v,
        })
        .context(VerificationSnafu)?;

    let digest = hash_eth_msg(msg);

    let recovered_pub_key = VerifyingKey::recover_from_digest(digest, &signature, recovery_id)
        .map_err(|_| AttestationVerificationError::KeyRecoveryError)
        .context(VerificationSnafu)?;

    let expected_key = VerifyingKey::from_sec1_bytes(pub_key)
        .map_err(|_| AttestationVerificationError::PublicKeyParsingError)
        .context(VerificationSnafu)?;

    match recovered_pub_key == expected_key {
        true => Ok(()),
        false => Err(AttestationError::VerificationError {
            source: AttestationVerificationError::InvalidPublicKeyRecovered,
        }),
    }
}

/// Hashes a message with the Ethereum-specific prefix.
///
/// # Arguments
/// * `message` - The message to hash.
///
/// Returns the hashed message.
fn hash_eth_msg(message: &[u8]) -> CoreWrapper<Keccak256Core> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    hasher
}

/// Creates an attestation message by concatenating the state root and block number.
///
/// # Arguments
/// * `state_root` - A reference to the state root, typically a cryptographic hash.
/// * `block_number` - The block number associated with this attestation.
///
/// # Returns
/// A `Vec<u8>` containing the serialized attestation message.
///
pub fn create_attestation_message<BN: Into<u64>>(
    state_root: impl AsRef<[u8]>,
    block_number: BN,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(state_root.as_ref().len() + core::mem::size_of::<u64>());
    msg.extend_from_slice(state_root.as_ref());
    msg.extend_from_slice(&block_number.into().to_be_bytes());
    msg
}

/// Now verify for each attestation and every commitment
pub fn verify_attestations(
    attestations: &[Attestation],
    table_commitment_with_proof: &IndexMap<String, TableCommitmentWithProof>,
) -> Result<(), AttestationError> {
    // Early filtering: extract table commitments attestations
    let table_commitments_attestations: Vec<_> = attestations
        .iter()
        .filter(|attestation| {
            let Attestation::EthereumAttestation { state_root, .. } = attestation;

            // Filter out state_roots with length != 33 or first byte != 0x00
            state_root.len() == 33 && state_root[0] == 0x00
        })
        .collect::<Vec<_>>();

    let is_valid = process_results(
        table_commitments_attestations
            .iter()
            .cartesian_product(table_commitment_with_proof.into_iter())
            .map(
                |(attestation, (table_id, commitment_with_proof))| -> Result<bool, AttestationError> {
                    // We need to verify
                    // 1. The signature on the attestation is valid
                    // 2. The [`TableCommitmentBytes`] is in fact a leaf in the attestation tree and that
                    //    the provided Merkle proof in [`TableCommitmentWithProof`] is valid for the leaf
                    //    with respect to the attestation's state root
                    let Attestation::EthereumAttestation {
                        state_root,
                        block_number,
                        signature,
                        proposed_pub_key,
                        ..
                    } = attestation;
                    let attestation_message = create_attestation_message(state_root, *block_number);
                    verify_eth_signature(&attestation_message, signature, proposed_pub_key)?;
                    // Remove the first byte for it is the AttestationDomain
                    let actual_state_root = &state_root[1..];
                    let encoded_root = hex::encode(actual_state_root);
                    let keccak_encoded_leaf = keccak256(&hex::encode(generate_commitment_leaf(
                        table_id.to_string(),
                        commitment_with_proof.commitment.clone(),
                    )))?;
                    Ok(verify_proof(
                        commitment_with_proof.merkle_proof.clone(),
                        &encoded_root,
                        &keccak_encoded_leaf,
                    )?)
                },
            ),
        |mut iter| iter.all(|ok| ok),
    )?;
    if !is_valid {
        return Err(AttestationError::VerificationError {
            source: AttestationVerificationError::FailureToVerifyMerkleProof,
        });
    }
    Ok(())
}
