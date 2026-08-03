use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(
    table_name = "memebank_transfer_idempotency",
    schema_name = "cliptown"
)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub operation: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub idempotency_key: String,
    pub request_sha256_base64: String,
    pub transfer_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
