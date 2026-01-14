use super::base::zk_query_models::{
    Attestation, AttestationsResponse, AttestedCommitments, CommitmentScheme, QueryResultsResponse,
    TableCommitmentWithProof,
};
use super::{base::attestation::verify_attestations, uppercase_accessor::UppercaseAccessor};
use nova_snark::provider::hyperkzg::VerifierKey;
use proof_of_sql::{
    base::{
        commitment::{CommitmentEvaluationProof, QueryCommitments, TableCommitment},
        database::{OwnedTable, TableRef},
        try_standard_binary_deserialization, try_standard_binary_serialization,
    },
    proof_primitive::hyperkzg::{
        HyperKZGCommitment, HyperKZGCommitmentEvaluationProof, HyperKZGEngine,
    },
    sql::{evm_proof_plan::EVMProofPlan, proof::QueryProof},
};

const HYPER_KZG_VERIFIER_SETUP_BYTES: &[u8; 160] = include_bytes!("hyper-kzg.bin");

pub fn proof_of_sql_verify(
    query_response_json: String,
    attestations_response_json: String,
) -> String {
    let setup: VerifierKey<HyperKZGEngine> =
        try_standard_binary_deserialization(HYPER_KZG_VERIFIER_SETUP_BYTES)
            .unwrap()
            .0;
    let query_response: QueryResultsResponse = serde_json::from_str(&query_response_json).unwrap();
    let attestations_response: AttestationsResponse =
        serde_json::from_str(&attestations_response_json).unwrap();
    let attestations = attestations_response.attestations.clone();
    verify_attestations(&attestations, &query_response.commitments.commitments).unwrap();
    let query_commitments: QueryCommitments<HyperKZGCommitment> = query_response
        .commitments
        .commitments
        .into_iter()
        .map(
            |(table_id, table_commitment_with_proof)| -> Result<
                (TableRef, TableCommitment<HyperKZGCommitment>),
                Box<dyn core::error::Error>,
            > {
                let table_ref = TableRef::try_from(table_id.as_str())?;
                let table_commitment: TableCommitment<HyperKZGCommitment> =
                    try_standard_binary_deserialization(&table_commitment_with_proof.commitment)?.0;
                Ok((table_ref, table_commitment))
            },
        )
        .collect::<Result<_, _>>()
        .unwrap();
    let uppercased_query_commitments = UppercaseAccessor(&query_commitments);
    let plan: EVMProofPlan = try_standard_binary_deserialization(&query_response.plan)
        .unwrap()
        .0;
    let proof: QueryProof<HyperKZGCommitmentEvaluationProof> =
        try_standard_binary_deserialization(&query_response.proof)
            .unwrap()
            .0;
    let result: OwnedTable<
        <HyperKZGCommitmentEvaluationProof as CommitmentEvaluationProof>::Scalar,
    > = try_standard_binary_deserialization(&query_response.results)
        .unwrap()
        .0;
    let result = proof
        .verify(&plan, &uppercased_query_commitments, result, &&setup, &[])
        .unwrap();
    let table: Vec<_> = result
        .table
        .inner_table()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let result = serde_json::to_string(&table).unwrap();
    result
}
