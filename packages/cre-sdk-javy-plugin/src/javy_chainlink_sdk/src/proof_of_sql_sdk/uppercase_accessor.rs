use proof_of_sql::base::{
    commitment::Commitment,
    database::{ColumnType, CommitmentAccessor, MetadataAccessor, SchemaAccessor, TableRef},
};
use sqlparser::ast::Ident;

pub fn uppercase_identifier(ident: Ident) -> Ident {
    let value = ident.value.to_uppercase();
    Ident { value, ..ident }
}

pub fn uppercase_table_ref(table_ref: TableRef) -> TableRef {
    TableRef::from_idents(
        table_ref.schema_id().cloned().map(uppercase_identifier),
        uppercase_identifier(table_ref.table_id().clone()),
    )
}

/// Generic wrapper of proof-of-sql `-Accessor` types that coerces to uppercase.
///
/// Sxt-chain generally stores identifiers in all uppercase.
/// The SDK uses accessors in this casing due to using a `QueryCommitments` built from chain data.
/// So, this wrapper helps bridge the gap between the casing of queries/proof plans to chain data.
#[derive(Clone)]
pub struct UppercaseAccessor<'a, A>(pub &'a A);

impl<SA> SchemaAccessor for UppercaseAccessor<'_, SA>
where
    SA: SchemaAccessor,
{
    fn lookup_column(&self, table_ref: &TableRef, column_id: &Ident) -> Option<ColumnType> {
        let ident = uppercase_identifier(column_id.clone());
        self.0
            .lookup_column(&uppercase_table_ref(table_ref.clone()), &ident)
    }

    fn lookup_schema(&self, table_ref: &TableRef) -> Vec<(Ident, ColumnType)> {
        self.0
            .lookup_schema(&uppercase_table_ref(table_ref.clone()))
            .into_iter()
            .map(|(ident, column_type)| {
                let ident = uppercase_identifier(ident);
                (ident, column_type)
            })
            .collect()
    }
}

impl<MA> MetadataAccessor for UppercaseAccessor<'_, MA>
where
    MA: MetadataAccessor,
{
    fn get_length(&self, table_ref: &TableRef) -> usize {
        let table_ref = uppercase_table_ref(table_ref.clone());

        self.0.get_length(&table_ref)
    }

    fn get_offset(&self, table_ref: &TableRef) -> usize {
        let table_ref = uppercase_table_ref(table_ref.clone());

        self.0.get_offset(&table_ref)
    }
}

impl<CA, C> CommitmentAccessor<C> for UppercaseAccessor<'_, CA>
where
    CA: CommitmentAccessor<C>,
    C: Commitment,
{
    fn get_commitment(&self, table_ref: &TableRef, column_id: &Ident) -> C {
        self.0.get_commitment(
            &uppercase_table_ref(table_ref.clone()),
            &uppercase_identifier(column_id.clone()),
        )
    }
}
