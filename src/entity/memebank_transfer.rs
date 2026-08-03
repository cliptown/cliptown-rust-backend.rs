use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "memebank_transfers", schema_name = "cliptown")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub transfer_id: Uuid,
    pub user_id: Uuid,
    pub contract_version: i16,
    pub direction: String,
    pub source_item_id: String,
    pub media_type: String,
    pub content_sha256_base64: String,
    pub content_length: i64,
    pub payload_algorithm: String,
    pub payload_nonce_base64: String,
    pub payload_ciphertext_base64: String,
    pub payload_associated_data_hash_base64: Option<String>,
    pub payload_key_id: String,
    pub metadata_algorithm: Option<String>,
    pub metadata_nonce_base64: Option<String>,
    pub metadata_ciphertext_base64: Option<String>,
    pub metadata_associated_data_hash_base64: Option<String>,
    pub metadata_key_id: Option<String>,
    pub state: String,
    pub client_receipt_id: Option<String>,
    pub expires_at: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
    pub acknowledged_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
