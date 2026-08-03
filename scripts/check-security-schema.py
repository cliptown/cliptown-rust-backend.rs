#!/usr/bin/env python3
"""Fail closed when reviewed ClipTown security SQL boundaries drift."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema" / "schema.sql"
MEMEBANK_SCHEMA = ROOT / "schema" / "memebank-integration.sql"
text = SCHEMA.read_text(encoding="utf-8")
memebank_text = MEMEBANK_SCHEMA.read_text(encoding="utf-8")

required = (
    "CREATE OR REPLACE FUNCTION cliptown.current_device_id()",
    "CREATE TABLE IF NOT EXISTS cliptown.device_verification_keys",
    "CREATE TABLE IF NOT EXISTS cliptown.app_vault_applications",
    "CREATE OR REPLACE FUNCTION cliptown.app_vault_application_allows(",
    "CREATE TABLE IF NOT EXISTS cliptown.app_vault_mutations",
    "CREATE TABLE IF NOT EXISTS cliptown.app_vault_record_heads",
    "CREATE TABLE IF NOT EXISTS cliptown.external_step_up_challenges",
    "CREATE TABLE IF NOT EXISTS cliptown.external_step_up_proofs",
    "CREATE OR REPLACE FUNCTION cliptown.consume_external_step_up(",
    "app_vault_record_heads_mutation_identity_fk",
    "transaction_timestamp()",
    "'app_vault_key'",
    "ALTER TABLE cliptown.app_vault_mutations ENABLE ROW LEVEL SECURITY",
    "CREATE POLICY app_vault_mutations_active_device_select",
    "CREATE POLICY app_vault_mutations_active_device_insert",
    "CREATE POLICY app_vault_record_heads_active_device_select",
)
missing = [needle for needle in required if needle not in text]
if missing:
    raise SystemExit(f"schema/schema.sql is missing app-vault security contracts: {missing}")


def table_block(table_name: str, source: str = text) -> str:
    marker = f"CREATE TABLE IF NOT EXISTS cliptown.{table_name}"
    start = source.find(marker)
    if start < 0:
        raise SystemExit(f"missing table {table_name}")
    end = source.find("\n);", start)
    if end < 0:
        raise SystemExit(f"unterminated table {table_name}")
    return source[start : end + 3].lower()


mutation = table_block("app_vault_mutations")
forbidden_mutation_columns = (
    " otp_seed ",
    " otp_code ",
    " access_token ",
    " refresh_token ",
    " password ",
    " pin ",
    " provider ",
    " account_label ",
    " title ",
    " preview ",
    " pinned ",
    " blind_terms ",
    " embedding ",
)
leaked = [column.strip() for column in forbidden_mutation_columns if column in mutation]
if leaked:
    raise SystemExit(f"app_vault_mutations leaked clipboard/authentication semantics: {leaked}")

challenge = table_block("external_step_up_challenges")
for field in (
    "method",
    "normalized_route",
    "target_resource_id",
    "request_body_sha256_base64",
    "initiating_device_id",
    "consumed_at",
    "invalidated_at",
):
    if field not in challenge:
        raise SystemExit(f"external_step_up_challenges is not request-bound: missing {field}")

proof = table_block("external_step_up_proofs")
for forbidden in ("access_token", "refresh_token", "cookie", "password", "otp_code", "vault_key"):
    if forbidden in proof:
        raise SystemExit(f"external_step_up_proofs became a credential container: {forbidden}")

if "GRANT SELECT ON TABLE cliptown.app_vault_applications TO PUBLIC" in text:
    raise SystemExit("application policy rows must not be visible through a PUBLIC table grant")
if "SET search_path = pg_catalog, cliptown" not in text:
    raise SystemExit("security-definer helpers must use a fixed search path")

if "p_now TIMESTAMPTZ" in text:
    raise SystemExit("proof consumption must use transaction time, not caller-controlled time")
if "app_vault_record_heads_mutation_identity_fk" not in text:
    raise SystemExit("record heads must bind every identity and ordering field to a mutation")
policy_start = text.index("CREATE POLICY external_step_up_challenges_initiating_device_select")
policy_end = text.index(";", policy_start)
if "lifecycle_state = 'active'" not in text[policy_start:policy_end]:
    raise SystemExit("revoked devices must not read pending step-up challenges")

if "FOR UPDATE OF challenge, proof" not in text:
    raise SystemExit("step-up consumption must lock the challenge and proof together")
if "lifecycle_state = 'active'" not in text:
    raise SystemExit("device-gated policies must require an active device")

memebank_required = (
    "CREATE TABLE IF NOT EXISTS cliptown.memebank_transfers",
    "CREATE TABLE IF NOT EXISTS cliptown.memebank_transfer_idempotency",
    "ALTER TABLE cliptown.memebank_transfers ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE cliptown.memebank_transfers FORCE ROW LEVEL SECURITY",
    "ALTER TABLE cliptown.memebank_transfer_idempotency ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE cliptown.memebank_transfer_idempotency FORCE ROW LEVEL SECURITY",
    "CREATE POLICY memebank_transfers_owner_select",
    "CREATE POLICY memebank_transfers_owner_insert",
    "CREATE POLICY memebank_transfers_owner_update",
    "CREATE POLICY memebank_transfer_idempotency_owner_select",
    "CREATE POLICY memebank_transfer_idempotency_owner_insert",
    "REVOKE ALL ON TABLE cliptown.memebank_transfers FROM PUBLIC",
    "REVOKE ALL ON TABLE cliptown.memebank_transfer_idempotency FROM PUBLIC",
)
missing = [needle for needle in memebank_required if needle not in memebank_text]
if missing:
    raise SystemExit(
        f"schema/memebank-integration.sql is missing security contracts: {missing}"
    )

transfer = table_block("memebank_transfers", memebank_text)
idempotency = table_block("memebank_transfer_idempotency", memebank_text)
for field in (
    "user_id uuid not null",
    "contract_version smallint not null check (contract_version = 1)",
    "payload_algorithm text not null",
    "payload_nonce_base64 text not null",
    "payload_ciphertext_base64 text not null",
    "payload_key_id text not null",
    "content_length bigint not null",
    "expires_at timestamptz not null",
):
    if field not in transfer:
        raise SystemExit(f"MemeBank transfer lost ciphertext boundary: {field}")
for field in (
    "user_id uuid not null",
    "operation text not null",
    "idempotency_key text not null",
    "request_sha256_base64 text not null",
    "transfer_id uuid not null",
):
    if field not in idempotency:
        raise SystemExit(f"MemeBank idempotency lost request binding: {field}")

for forbidden in (
    "access_token",
    "refresh_token",
    "bearer_token",
    "otp_code",
    "otp_seed",
    "private_key",
    "provider_credential",
    "signed_url",
    "durable_url",
    "plaintext",
    "ocr_text",
    "caption",
    "app_install_state",
    "deep_link",
    "local_path",
):
    if forbidden in transfer:
        raise SystemExit(f"MemeBank transfer became a credential/plaintext container: {forbidden}")

for invariant in (
    "content_length between 0 and 16777216",
    "octet_length(payload_ciphertext_base64) between 1 and 22369624",
    "expires_at <= created_at + interval '7 days'",
    "unique (user_id, transfer_id)",
):
    if invariant not in transfer:
        raise SystemExit(f"MemeBank transfer lost bounded invariant: {invariant}")

print(
    "app-vault, external step-up, and MemeBank delegated-transfer boundaries are fail-closed"
)
