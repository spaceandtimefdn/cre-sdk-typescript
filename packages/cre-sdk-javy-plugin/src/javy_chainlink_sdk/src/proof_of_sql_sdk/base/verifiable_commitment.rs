use indexmap::IndexMap;
use proof_of_sql::{
    base::{
        commitment::{QueryCommitments, TableCommitment},
        database::TableRef,
        try_standard_binary_deserialization,
    },
    proof_primitive::hyperkzg::HyperKZGCommitment,
};

use super::zk_query_models::TableCommitmentWithProof;
/// Adapted from attestation tree code in `sxt-node`
/// This replicates the exact encoding logic from [`CommitmentMapPrefixFoliate`]
///
/// # Panics
/// Panics if the table identifier length exceeds 255 bytes.
pub fn generate_commitment_leaf(
    table_identifier: String,
    table_commitment_bytes: Vec<u8>,
) -> Vec<u8> {
    let table_identifier_utf8: Vec<u8> = table_identifier.into_bytes().to_vec();
    // the table identifier length should never exceed 255
    let table_identifier_length_prefix = u8::try_from(table_identifier_utf8.len())
        .expect("table identifier length should never exceed 255");

    // Encode key: [length_prefix][table_identifier_utf8][commitment_scheme_encoded]
    // Encode value: raw commitment bytes (matching sxt-node's value.data.into_inner())
    // Combine key and value (matching encode_key_value_leaf from sxt-node)
    core::iter::once(table_identifier_length_prefix)
        .chain(table_identifier_utf8)
        .chain(core::iter::once(0u8))
        .chain(table_commitment_bytes)
        .collect()
}

/// Extract [`QueryCommitments`] from an index map of [`TableCommitment`]s.
#[expect(clippy::type_complexity)]
pub fn extract_query_commitments_from_table_commitments_with_proof(
    table_commitments_with_proof: IndexMap<String, TableCommitmentWithProof>,
) -> Result<QueryCommitments<HyperKZGCommitment>, Box<dyn core::error::Error>> {
    // Convert bytes -> TableCommitment<T> and collect
    let query_commitments: QueryCommitments<HyperKZGCommitment> = table_commitments_with_proof
        .into_iter()
        .map(
            |(table_id, table_commitment_with_proof)| -> Result<
                (TableRef, TableCommitment<HyperKZGCommitment>),
                Box<dyn core::error::Error>,
            > {
                let table_ref = TableRef::try_from(table_id.as_str())?;
                let table_commitment: TableCommitment<HyperKZGCommitment> =
                    try_standard_binary_deserialization(
                        &table_commitment_with_proof.commitment, // or the correct bytes field
                    )?
                    .0;
                Ok((table_ref, table_commitment))
            },
        )
        .collect::<Result<_, _>>()?;
    Ok(query_commitments)
}
