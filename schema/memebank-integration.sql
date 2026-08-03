-- BEGIN DEN-1578 MEMEBANK DELEGATED TRANSFER API
--
-- This is the ClipTown persistence boundary for the API-first MemeBank
-- integration. It stores ciphertext and bounded integrity/routing metadata only.
-- Shared-auth delegated bearer verification happens before setting
-- request.jwt.claim.sub; no factor-specific proof or app-install state is stored.

CREATE TABLE IF NOT EXISTS cliptown.memebank_transfers (
    transfer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    contract_version SMALLINT NOT NULL CHECK (contract_version = 1),
    direction TEXT NOT NULL CHECK (direction IN (
        'memebank_to_cliptown', 'cliptown_to_memebank'
    )),
    source_item_id TEXT NOT NULL CHECK (
        char_length(source_item_id) BETWEEN 1 AND 128
        AND source_item_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    media_type TEXT NOT NULL CHECK (
        char_length(media_type) BETWEEN 3 AND 128
        AND media_type ~ '^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$'
    ),
    content_sha256_base64 TEXT NOT NULL CHECK (
        octet_length(content_sha256_base64) BETWEEN 43 AND 44
        AND content_sha256_base64 ~ '^[A-Za-z0-9_-]{43}=?$'
    ),
    content_length BIGINT NOT NULL CHECK (
        content_length BETWEEN 0 AND 16777216
    ),
    payload_algorithm TEXT NOT NULL CHECK (payload_algorithm IN (
        'xchacha20poly1305-v1', 'aes-256-gcm-v1'
    )),
    payload_nonce_base64 TEXT NOT NULL CHECK (
        octet_length(payload_nonce_base64) BETWEEN 16 AND 128
    ),
    payload_ciphertext_base64 TEXT NOT NULL CHECK (
        octet_length(payload_ciphertext_base64) BETWEEN 1 AND 22369624
    ),
    payload_associated_data_hash_base64 TEXT CHECK (
        payload_associated_data_hash_base64 IS NULL
        OR octet_length(payload_associated_data_hash_base64) BETWEEN 1 AND 128
    ),
    payload_key_id TEXT NOT NULL CHECK (
        char_length(payload_key_id) BETWEEN 1 AND 128
        AND payload_key_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    metadata_algorithm TEXT CHECK (
        metadata_algorithm IS NULL OR metadata_algorithm IN (
            'xchacha20poly1305-v1', 'aes-256-gcm-v1'
        )
    ),
    metadata_nonce_base64 TEXT CHECK (
        metadata_nonce_base64 IS NULL
        OR octet_length(metadata_nonce_base64) BETWEEN 16 AND 128
    ),
    metadata_ciphertext_base64 TEXT CHECK (
        metadata_ciphertext_base64 IS NULL
        OR octet_length(metadata_ciphertext_base64) BETWEEN 1 AND 22369624
    ),
    metadata_associated_data_hash_base64 TEXT CHECK (
        metadata_associated_data_hash_base64 IS NULL
        OR octet_length(metadata_associated_data_hash_base64) BETWEEN 1 AND 128
    ),
    metadata_key_id TEXT CHECK (
        metadata_key_id IS NULL OR (
            char_length(metadata_key_id) BETWEEN 1 AND 128
            AND metadata_key_id ~ '^[A-Za-z0-9._:-]+$'
        )
    ),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN (
        'pending', 'acknowledged', 'ignored', 'rejected',
        'expired', 'cancelled'
    )),
    client_receipt_id TEXT CHECK (
        client_receipt_id IS NULL OR (
            char_length(client_receipt_id) BETWEEN 16 AND 128
            AND client_receipt_id ~ '^[A-Za-z0-9._:-]+$'
        )
    ),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    acknowledged_at TIMESTAMPTZ,
    UNIQUE (user_id, transfer_id),
    CONSTRAINT memebank_transfers_retention_bounded CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '7 days'
    ),
    CONSTRAINT memebank_transfers_metadata_complete CHECK (
        (
            metadata_algorithm IS NULL
            AND metadata_nonce_base64 IS NULL
            AND metadata_ciphertext_base64 IS NULL
            AND metadata_associated_data_hash_base64 IS NULL
            AND metadata_key_id IS NULL
        )
        OR (
            metadata_algorithm IS NOT NULL
            AND metadata_nonce_base64 IS NOT NULL
            AND metadata_ciphertext_base64 IS NOT NULL
            AND metadata_key_id IS NOT NULL
        )
    ),
    CONSTRAINT memebank_transfers_acknowledgement_consistent CHECK (
        (
            state IN ('acknowledged', 'ignored', 'rejected')
            AND acknowledged_at IS NOT NULL
            AND client_receipt_id IS NOT NULL
        )
        OR (
            state IN ('pending', 'expired', 'cancelled')
            AND acknowledged_at IS NULL
            AND client_receipt_id IS NULL
        )
    ),
    CONSTRAINT memebank_transfers_timestamps_ordered CHECK (
        updated_at >= created_at
        AND (acknowledged_at IS NULL OR acknowledged_at BETWEEN created_at AND updated_at)
    )
);
CREATE INDEX IF NOT EXISTS memebank_transfers_owner_cursor_idx
    ON cliptown.memebank_transfers (user_id, created_at DESC, transfer_id DESC);
CREATE INDEX IF NOT EXISTS memebank_transfers_owner_state_idx
    ON cliptown.memebank_transfers (user_id, state, direction, created_at DESC);
CREATE INDEX IF NOT EXISTS memebank_transfers_pending_expiry_idx
    ON cliptown.memebank_transfers (expires_at, user_id)
    WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS cliptown.memebank_transfer_idempotency (
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK (operation IN ('create', 'acknowledge')),
    idempotency_key TEXT NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 16 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9._:-]+$'
    ),
    request_sha256_base64 TEXT NOT NULL CHECK (
        octet_length(request_sha256_base64) BETWEEN 43 AND 44
        AND request_sha256_base64 ~ '^[A-Za-z0-9_-]{43}=?$'
    ),
    transfer_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, operation, idempotency_key),
    CONSTRAINT memebank_transfer_idempotency_transfer_owner_fk
        FOREIGN KEY (user_id, transfer_id)
        REFERENCES cliptown.memebank_transfers(user_id, transfer_id)
        ON DELETE CASCADE,
    CONSTRAINT memebank_transfer_idempotency_retention_bounded CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '30 days'
    )
);
CREATE INDEX IF NOT EXISTS memebank_transfer_idempotency_expiry_idx
    ON cliptown.memebank_transfer_idempotency (expires_at);

ALTER TABLE cliptown.memebank_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.memebank_transfers FORCE ROW LEVEL SECURITY;
ALTER TABLE cliptown.memebank_transfer_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.memebank_transfer_idempotency FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS memebank_transfers_owner_select
    ON cliptown.memebank_transfers;
CREATE POLICY memebank_transfers_owner_select
    ON cliptown.memebank_transfers
    FOR SELECT
    USING (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS memebank_transfers_owner_insert
    ON cliptown.memebank_transfers;
CREATE POLICY memebank_transfers_owner_insert
    ON cliptown.memebank_transfers
    FOR INSERT
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS memebank_transfers_owner_update
    ON cliptown.memebank_transfers;
CREATE POLICY memebank_transfers_owner_update
    ON cliptown.memebank_transfers
    FOR UPDATE
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS memebank_transfer_idempotency_owner_select
    ON cliptown.memebank_transfer_idempotency;
CREATE POLICY memebank_transfer_idempotency_owner_select
    ON cliptown.memebank_transfer_idempotency
    FOR SELECT
    USING (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS memebank_transfer_idempotency_owner_insert
    ON cliptown.memebank_transfer_idempotency;
CREATE POLICY memebank_transfer_idempotency_owner_insert
    ON cliptown.memebank_transfer_idempotency
    FOR INSERT
    WITH CHECK (user_id = cliptown.current_user_id());

REVOKE ALL ON TABLE cliptown.memebank_transfers FROM PUBLIC;
REVOKE ALL ON TABLE cliptown.memebank_transfer_idempotency FROM PUBLIC;

-- END DEN-1578 MEMEBANK DELEGATED TRANSFER API
