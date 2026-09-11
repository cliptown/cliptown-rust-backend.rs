-- ClipTown portable encrypted-backup desired state.
--
-- This file is deliberately limited to PostgreSQL/CockroachDB common DDL and
-- is verified by declarative-migrations/dpm against real instances of both
-- engines. It contains only ciphertext and bounded routing/integrity metadata.
-- Clipboard plaintext, source file paths, content keys, plaintext embeddings,
-- credential-store values, and R2 credentials are forbidden.

CREATE SCHEMA IF NOT EXISTS cliptown_backup;

CREATE TABLE cliptown_backup.encrypted_clip_backups (
    account_id UUID NOT NULL,
    clip_id UUID NOT NULL,
    source_device_id UUID NOT NULL,
    clip_kind TEXT NOT NULL CHECK (
        clip_kind IN ('text', 'rich_text', 'link', 'email', 'color', 'code', 'image', 'files')
    ),
    envelope_cipher_version TEXT NOT NULL CHECK (
        envelope_cipher_version IN ('xchacha20poly1305-v1', 'aes-256-gcm-v1')
    ),
    envelope_ciphertext BYTEA NOT NULL CHECK (
        octet_length(envelope_ciphertext) BETWEEN 17 AND 16777216
    ),
    envelope_nonce BYTEA NOT NULL CHECK (octet_length(envelope_nonce) BETWEEN 12 AND 24),
    associated_data_sha256 BYTEA NOT NULL CHECK (octet_length(associated_data_sha256) = 32),
    logical_clock INT8 NOT NULL CHECK (logical_clock >= 0),
    pinned BOOL NOT NULL DEFAULT false,
    deleted BOOL NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (account_id, clip_id)
);

CREATE INDEX encrypted_clip_backups_account_clock_idx
    ON cliptown_backup.encrypted_clip_backups (account_id, logical_clock, clip_id);

CREATE TABLE cliptown_backup.encrypted_embedding_backups (
    account_id UUID NOT NULL,
    clip_id UUID NOT NULL,
    source_device_id UUID NOT NULL,
    embedding_cipher_version TEXT NOT NULL CHECK (
        embedding_cipher_version IN ('xchacha20poly1305-v1', 'aes-256-gcm-v1')
    ),
    model_id_ciphertext BYTEA NOT NULL CHECK (
        octet_length(model_id_ciphertext) BETWEEN 17 AND 2048
    ),
    vector_dimensions INT8 NOT NULL CHECK (vector_dimensions BETWEEN 1 AND 8192),
    vector_ciphertext BYTEA NOT NULL CHECK (
        octet_length(vector_ciphertext) BETWEEN 17 AND 67108864
    ),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) BETWEEN 12 AND 24),
    associated_data_sha256 BYTEA NOT NULL CHECK (octet_length(associated_data_sha256) = 32),
    opted_in_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at >= opted_in_at),
    PRIMARY KEY (account_id, clip_id),
    CONSTRAINT encrypted_embedding_backups_clip_fk
        FOREIGN KEY (account_id, clip_id)
        REFERENCES cliptown_backup.encrypted_clip_backups (account_id, clip_id)
        ON DELETE CASCADE
);

CREATE TABLE cliptown_backup.encrypted_object_manifests (
    account_id UUID NOT NULL,
    object_id UUID NOT NULL,
    clip_id UUID NOT NULL,
    source_device_id UUID NOT NULL,
    payload_kind TEXT NOT NULL CHECK (payload_kind IN ('image', 'file')),
    content_cipher_version TEXT NOT NULL CHECK (
        content_cipher_version IN ('xchacha20poly1305-chunked-v1', 'aes-256-gcm-chunked-v1')
    ),
    encrypted_manifest BYTEA NOT NULL CHECK (
        octet_length(encrypted_manifest) BETWEEN 17 AND 16777216
    ),
    manifest_nonce BYTEA NOT NULL CHECK (octet_length(manifest_nonce) BETWEEN 12 AND 24),
    associated_data_sha256 BYTEA NOT NULL CHECK (octet_length(associated_data_sha256) = 32),
    randomized_storage_prefix TEXT NOT NULL UNIQUE CHECK (
        char_length(randomized_storage_prefix) BETWEEN 32 AND 256
        AND randomized_storage_prefix NOT LIKE '/%'
        AND randomized_storage_prefix NOT LIKE '%..%'
    ),
    plaintext_length INT8 NOT NULL CHECK (plaintext_length >= 0),
    ciphertext_length INT8 NOT NULL CHECK (ciphertext_length > 0),
    expected_chunk_count INT8 NOT NULL CHECK (expected_chunk_count BETWEEN 1 AND 100000),
    upload_state TEXT NOT NULL CHECK (
        upload_state IN ('planned', 'uploading', 'complete', 'deleting', 'deleted')
    ),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at >= created_at),
    deleted_at TIMESTAMPTZ,
    PRIMARY KEY (account_id, object_id),
    CONSTRAINT encrypted_object_manifests_clip_fk
        FOREIGN KEY (account_id, clip_id)
        REFERENCES cliptown_backup.encrypted_clip_backups (account_id, clip_id)
        ON DELETE CASCADE,
    CONSTRAINT encrypted_object_manifests_delete_state CHECK (
        (upload_state = 'deleted' AND deleted_at IS NOT NULL)
        OR (upload_state <> 'deleted' AND deleted_at IS NULL)
    )
);

CREATE INDEX encrypted_object_manifests_clip_idx
    ON cliptown_backup.encrypted_object_manifests (account_id, clip_id, object_id);

CREATE TABLE cliptown_backup.encrypted_object_chunks (
    account_id UUID NOT NULL,
    object_id UUID NOT NULL,
    chunk_index INT8 NOT NULL CHECK (chunk_index >= 0),
    randomized_storage_key TEXT NOT NULL UNIQUE CHECK (
        char_length(randomized_storage_key) BETWEEN 32 AND 512
        AND randomized_storage_key NOT LIKE '/%'
        AND randomized_storage_key NOT LIKE '%..%'
    ),
    ciphertext_length INT8 NOT NULL CHECK (ciphertext_length > 0),
    ciphertext_sha256 BYTEA NOT NULL CHECK (octet_length(ciphertext_sha256) = 32),
    provider_etag TEXT CHECK (
        provider_etag IS NULL OR char_length(provider_etag) BETWEEN 1 AND 256
    ),
    uploaded_at TIMESTAMPTZ,
    PRIMARY KEY (account_id, object_id, chunk_index),
    CONSTRAINT encrypted_object_chunks_manifest_fk
        FOREIGN KEY (account_id, object_id)
        REFERENCES cliptown_backup.encrypted_object_manifests (account_id, object_id)
        ON DELETE CASCADE
);
