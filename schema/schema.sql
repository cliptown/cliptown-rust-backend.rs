-- ClipTown reviewed PostgreSQL desired state.
--
-- Never run this automatically at API startup. Apply only through the reviewed
-- declarative migration workflow. PostgreSQL/Supabase and Cloudflare R2 store
-- ciphertext and bounded routing metadata, never clipboard plaintext, content
-- keys, PINs, biometric templates, Signal private keys, or OTP codes.

CREATE SCHEMA IF NOT EXISTS cliptown;

CREATE OR REPLACE FUNCTION cliptown.current_user_id()
RETURNS UUID
LANGUAGE SQL
STABLE
AS $$
    SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

CREATE TABLE IF NOT EXISTS cliptown.accounts (
    user_id UUID PRIMARY KEY,
    device_list_revision BIGINT NOT NULL DEFAULT 0 CHECK (device_list_revision >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cliptown.devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    platform TEXT NOT NULL CHECK (char_length(platform) BETWEEN 1 AND 64),
    lifecycle_state TEXT NOT NULL DEFAULT 'pending' CHECK (
        lifecycle_state IN ('pending', 'active', 'suspended', 'revoked')
    ),
    sync_token_hash TEXT NOT NULL,
    identity_key_fingerprint_base64 TEXT,
    local_unlock_policy JSONB NOT NULL DEFAULT '{"pin_enabled":false,"biometric_enabled":false,"passkey_enabled":false}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    suspended_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, id),
    CONSTRAINT devices_revocation_consistent CHECK (
        (lifecycle_state = 'revoked' AND revoked_at IS NOT NULL)
        OR (lifecycle_state <> 'revoked' AND revoked_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS devices_user_state_idx
    ON cliptown.devices (user_id, lifecycle_state, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS devices_sync_token_hash_idx
    ON cliptown.devices (sync_token_hash);

CREATE TABLE IF NOT EXISTS cliptown.signal_prekey_bundles (
    device_id UUID PRIMARY KEY REFERENCES cliptown.devices(id) ON DELETE CASCADE,
    protocol_version SMALLINT NOT NULL CHECK (protocol_version = 1),
    registration_id BIGINT NOT NULL CHECK (registration_id > 0),
    identity_key_base64 TEXT NOT NULL,
    signed_prekey_id BIGINT NOT NULL CHECK (signed_prekey_id >= 0),
    signed_prekey_base64 TEXT NOT NULL,
    signed_prekey_signature_base64 TEXT NOT NULL,
    pq_signed_prekey_id BIGINT NOT NULL CHECK (pq_signed_prekey_id >= 0),
    pq_signed_prekey_base64 TEXT NOT NULL,
    pq_signed_prekey_signature_base64 TEXT NOT NULL,
    bundle_revision BIGINT NOT NULL CHECK (bundle_revision > 0),
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > published_at)
);

CREATE TABLE IF NOT EXISTS cliptown.signal_one_time_prekeys (
    device_id UUID NOT NULL REFERENCES cliptown.devices(id) ON DELETE CASCADE,
    prekey_id BIGINT NOT NULL CHECK (prekey_id >= 0),
    public_key_base64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ,
    claimed_by_device_id UUID REFERENCES cliptown.devices(id) ON DELETE SET NULL,
    PRIMARY KEY (device_id, prekey_id),
    CONSTRAINT signal_one_time_prekey_claim_consistent CHECK (
        (claimed_at IS NULL AND claimed_by_device_id IS NULL)
        OR (claimed_at IS NOT NULL AND claimed_by_device_id IS NOT NULL)
    ),
    CONSTRAINT signal_one_time_prekey_not_self_claimed CHECK (
        claimed_by_device_id IS NULL OR claimed_by_device_id <> device_id
    )
);
CREATE INDEX IF NOT EXISTS signal_one_time_prekeys_available_idx
    ON cliptown.signal_one_time_prekeys (device_id, prekey_id)
    WHERE claimed_at IS NULL;

CREATE TABLE IF NOT EXISTS cliptown.device_mailbox (
    server_sequence BIGSERIAL UNIQUE,
    envelope_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL,
    recipient_device_id UUID NOT NULL,
    protocol_version SMALLINT NOT NULL CHECK (protocol_version = 1),
    session_id TEXT NOT NULL CHECK (char_length(session_id) BETWEEN 1 AND 128),
    message_number NUMERIC(20, 0) NOT NULL CHECK (message_number >= 0),
    purpose TEXT NOT NULL CHECK (purpose IN (
        'account_key_transfer', 'clip_key', 'object_key', 'device_control',
        'recovery_package', 'acknowledgement', 'app_vault_key'
    )),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (
        expires_at > created_at AND expires_at <= created_at + INTERVAL '30 days'
    ),
    ciphertext_base64 TEXT NOT NULL CHECK (octet_length(ciphertext_base64) BETWEEN 1 AND 699052),
    queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    CONSTRAINT mailbox_sender_not_recipient CHECK (sender_device_id <> recipient_device_id),
    CONSTRAINT mailbox_sender_user_fk FOREIGN KEY (user_id, sender_device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE CASCADE,
    CONSTRAINT mailbox_recipient_user_fk FOREIGN KEY (user_id, recipient_device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS device_mailbox_recipient_cursor_idx
    ON cliptown.device_mailbox (recipient_device_id, server_sequence)
    WHERE acknowledged_at IS NULL;

CREATE TABLE IF NOT EXISTS cliptown.recovery_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('email', 'phone')),
    destination_ciphertext TEXT NOT NULL,
    destination_key_id TEXT NOT NULL,
    destination_blind_digest TEXT NOT NULL,
    masked_destination TEXT NOT NULL CHECK (char_length(masked_destination) BETWEEN 3 AND 320),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    UNIQUE (user_id, kind, destination_blind_digest)
);

CREATE TABLE IF NOT EXISTS cliptown.recovery_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    channel_id UUID NOT NULL REFERENCES cliptown.recovery_channels(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN (
        'add_device', 'account_recovery', 'step_up', 'change_channel', 'revoke_device'
    )),
    code_digest TEXT NOT NULL,
    digest_key_id TEXT NOT NULL,
    attempts_remaining SMALLINT NOT NULL DEFAULT 5 CHECK (attempts_remaining BETWEEN 0 AND 10),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (
        expires_at > requested_at AND expires_at <= requested_at + INTERVAL '15 minutes'
    ),
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    requester_risk_hash TEXT,
    CONSTRAINT recovery_challenge_terminal_state CHECK (
        consumed_at IS NULL OR invalidated_at IS NULL
    )
);
CREATE INDEX IF NOT EXISTS recovery_challenges_active_idx
    ON cliptown.recovery_challenges (user_id, channel_id, expires_at)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE IF NOT EXISTS cliptown.encrypted_recovery_packages (
    user_id UUID PRIMARY KEY REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    package_version SMALLINT NOT NULL CHECK (package_version = 1),
    recovery_key_id TEXT NOT NULL,
    ciphertext_base64 TEXT NOT NULL,
    nonce_base64 TEXT NOT NULL,
    associated_data_hash_base64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cliptown.clips (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    nonce TEXT NOT NULL,
    associated_data_hash TEXT,
    key_id TEXT NOT NULL,
    pinned BOOLEAN NOT NULL DEFAULT false,
    deleted BOOLEAN NOT NULL DEFAULT false,
    blind_terms JSONB NOT NULL DEFAULT '[]'::jsonb,
    encrypted_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_device_id UUID NOT NULL,
    logical_clock BIGINT NOT NULL CHECK (logical_clock >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, id),
    CONSTRAINT clips_source_device_user_fk FOREIGN KEY (user_id, source_device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS clips_user_clock_idx
    ON cliptown.clips (user_id, logical_clock, id);

-- Local SQLite remains the searchable source of truth for embeddings. Cloud
-- backup is explicit opt-in and stores one device-encrypted vector envelope;
-- neither PostgreSQL nor CockroachDB receives a plaintext model identifier or
-- vector that could be searched server-side.
CREATE TABLE IF NOT EXISTS cliptown.encrypted_embedding_backups (
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    clip_id UUID NOT NULL,
    source_device_id UUID NOT NULL,
    embedding_cipher_version TEXT NOT NULL CHECK (
        embedding_cipher_version IN ('xchacha20poly1305-v1', 'aes-256-gcm-v1')
    ),
    model_id_ciphertext_base64 TEXT NOT NULL CHECK (
        octet_length(model_id_ciphertext_base64) BETWEEN 24 AND 2732
    ),
    vector_dimensions INTEGER NOT NULL CHECK (vector_dimensions BETWEEN 1 AND 8192),
    vector_ciphertext_base64 TEXT NOT NULL CHECK (
        octet_length(vector_ciphertext_base64) BETWEEN 24 AND 89478488
    ),
    nonce_base64 TEXT NOT NULL CHECK (octet_length(nonce_base64) BETWEEN 16 AND 32),
    associated_data_hash_base64 TEXT NOT NULL CHECK (
        octet_length(associated_data_hash_base64) BETWEEN 43 AND 88
    ),
    key_id TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    opted_in_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at >= opted_in_at),
    PRIMARY KEY (user_id, clip_id),
    CONSTRAINT encrypted_embedding_backups_clip_fk FOREIGN KEY (user_id, clip_id)
        REFERENCES cliptown.clips(user_id, id) ON DELETE CASCADE,
    CONSTRAINT encrypted_embedding_backups_device_fk FOREIGN KEY (user_id, source_device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS encrypted_embedding_backups_device_idx
    ON cliptown.encrypted_embedding_backups (user_id, source_device_id, updated_at);

CREATE TABLE IF NOT EXISTS cliptown.encrypted_objects (
    id UUID PRIMARY KEY,
    manifest_id UUID NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    clip_id UUID NOT NULL,
    content_cipher_version TEXT NOT NULL CHECK (content_cipher_version IN (
        'xchacha20poly1305-chunked-v1', 'aes-256-gcm-chunked-v1'
    )),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    ciphertext_length BIGINT NOT NULL CHECK (ciphertext_length > 0),
    chunk_size INTEGER NOT NULL CHECK (chunk_size BETWEEN 65536 AND 16777216),
    ciphertext_sha256_base64 TEXT NOT NULL,
    encrypted_metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT encrypted_objects_clip_user_fk FOREIGN KEY (user_id, clip_id)
        REFERENCES cliptown.clips(user_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cliptown.encrypted_object_chunks (
    object_id UUID NOT NULL REFERENCES cliptown.encrypted_objects(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    ciphertext_length BIGINT NOT NULL CHECK (ciphertext_length > 0),
    ciphertext_sha256_base64 TEXT NOT NULL,
    nonce_base64 TEXT NOT NULL,
    randomized_storage_key TEXT NOT NULL UNIQUE CHECK (
        char_length(randomized_storage_key) BETWEEN 16 AND 512
        AND randomized_storage_key NOT LIKE '/%'
        AND randomized_storage_key NOT LIKE '%..%'
    ),
    uploaded_at TIMESTAMPTZ,
    PRIMARY KEY (object_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS cliptown.object_wrapped_keys (
    object_id UUID NOT NULL REFERENCES cliptown.encrypted_objects(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES cliptown.devices(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm IN (
        'signal-envelope-v1', 'xchacha20poly1305-wrap-v1', 'aes-256-gcm-wrap-v1'
    )),
    nonce_base64 TEXT NOT NULL,
    wrapped_key_base64 TEXT NOT NULL,
    associated_data_hash_base64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (object_id, recipient_device_id)
);

CREATE TABLE IF NOT EXISTS cliptown.object_upload_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    object_id UUID NOT NULL REFERENCES cliptown.encrypted_objects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    expected_chunk_count INTEGER NOT NULL CHECK (expected_chunk_count BETWEEN 1 AND 100000),
    expected_ciphertext_length BIGINT NOT NULL CHECK (expected_ciphertext_length > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (
        expires_at > created_at AND expires_at <= created_at + INTERVAL '1 hour'
    ),
    completed_at TIMESTAMPTZ,
    UNIQUE (user_id, idempotency_key)
);

ALTER TABLE cliptown.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.recovery_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.recovery_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.encrypted_recovery_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.clips ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.encrypted_embedding_backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.encrypted_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.encrypted_object_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.object_wrapped_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.object_upload_sessions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS accounts_owner_policy ON cliptown.accounts;
CREATE POLICY accounts_owner_policy ON cliptown.accounts
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS devices_owner_policy ON cliptown.devices;
CREATE POLICY devices_owner_policy ON cliptown.devices
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS recovery_channels_owner_policy ON cliptown.recovery_channels;
CREATE POLICY recovery_channels_owner_policy ON cliptown.recovery_channels
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS recovery_challenges_owner_policy ON cliptown.recovery_challenges;
CREATE POLICY recovery_challenges_owner_policy ON cliptown.recovery_challenges
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS encrypted_recovery_packages_owner_policy ON cliptown.encrypted_recovery_packages;
CREATE POLICY encrypted_recovery_packages_owner_policy ON cliptown.encrypted_recovery_packages
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS clips_owner_policy ON cliptown.clips;
CREATE POLICY clips_owner_policy ON cliptown.clips
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS encrypted_embedding_backups_owner_policy
    ON cliptown.encrypted_embedding_backups;
CREATE POLICY encrypted_embedding_backups_owner_policy
    ON cliptown.encrypted_embedding_backups
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS encrypted_objects_owner_policy ON cliptown.encrypted_objects;
CREATE POLICY encrypted_objects_owner_policy ON cliptown.encrypted_objects
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

DROP POLICY IF EXISTS encrypted_object_chunks_owner_policy
    ON cliptown.encrypted_object_chunks;
CREATE POLICY encrypted_object_chunks_owner_policy
    ON cliptown.encrypted_object_chunks
    USING (EXISTS (
        SELECT 1
        FROM cliptown.encrypted_objects AS object
        WHERE object.id = object_id
          AND object.user_id = cliptown.current_user_id()
    ))
    WITH CHECK (EXISTS (
        SELECT 1
        FROM cliptown.encrypted_objects AS object
        WHERE object.id = object_id
          AND object.user_id = cliptown.current_user_id()
    ));

DROP POLICY IF EXISTS object_wrapped_keys_owner_policy ON cliptown.object_wrapped_keys;
CREATE POLICY object_wrapped_keys_owner_policy ON cliptown.object_wrapped_keys
    USING (EXISTS (
        SELECT 1
        FROM cliptown.encrypted_objects AS object
        WHERE object.id = object_id
          AND object.user_id = cliptown.current_user_id()
    ))
    WITH CHECK (EXISTS (
        SELECT 1
        FROM cliptown.encrypted_objects AS object
        WHERE object.id = object_id
          AND object.user_id = cliptown.current_user_id()
    ));

DROP POLICY IF EXISTS object_upload_sessions_owner_policy ON cliptown.object_upload_sessions;
CREATE POLICY object_upload_sessions_owner_policy ON cliptown.object_upload_sessions
    USING (user_id = cliptown.current_user_id())
    WITH CHECK (user_id = cliptown.current_user_id());

REVOKE ALL ON ALL TABLES IN SCHEMA cliptown FROM PUBLIC;

-- BEGIN DEN-44 APP VAULT AND EXTERNAL STEP-UP
--
-- Application-vault records are not clipboard records. This schema stores only
-- ciphertext/tombstones and bounded routing metadata. External step-up proofs
-- are one-time authorization artifacts, never primary sessions or bearer tokens.

CREATE OR REPLACE FUNCTION cliptown.current_device_id()
RETURNS UUID
LANGUAGE SQL
STABLE
AS $$
    SELECT NULLIF(current_setting('request.jwt.claim.device_id', true), '')::uuid
$$;

CREATE TABLE IF NOT EXISTS cliptown.device_verification_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('device_auth', 'app_vault_mutation')),
    algorithm TEXT NOT NULL CHECK (algorithm IN (
        'ed25519-v1', 'p256-v1', 'signal-identity-v1'
    )),
    key_id TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    public_key_base64 TEXT NOT NULL CHECK (octet_length(public_key_base64) BETWEEN 16 AND 16384),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, device_id, purpose, key_id),
    CONSTRAINT device_verification_keys_device_user_fk
        FOREIGN KEY (user_id, device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS device_verification_keys_active_idx
    ON cliptown.device_verification_keys (user_id, device_id, purpose, key_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS cliptown.app_vault_applications (
    app_id TEXT PRIMARY KEY CHECK (
        char_length(app_id) BETWEEN 1 AND 128
        AND app_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    enabled BOOLEAN NOT NULL DEFAULT false,
    allowed_namespaces JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(allowed_namespaces) = 'array'
    ),
    max_batch_size INTEGER NOT NULL CHECK (max_batch_size BETWEEN 1 AND 500),
    max_ciphertext_base64_length INTEGER NOT NULL CHECK (
        max_ciphertext_base64_length BETWEEN 1 AND 699052
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now() CHECK (updated_at >= created_at)
);

CREATE OR REPLACE FUNCTION cliptown.app_vault_application_allows(
    p_app_id TEXT,
    p_namespace TEXT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, cliptown
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM cliptown.app_vault_applications AS application
        WHERE application.app_id = p_app_id
          AND application.enabled
          AND application.allowed_namespaces @> jsonb_build_array(p_namespace)
    )
$$;

INSERT INTO cliptown.app_vault_applications (
    app_id,
    enabled,
    allowed_namespaces,
    max_batch_size,
    max_ciphertext_base64_length
)
VALUES (
    'app.3fa.authenticator',
    false,
    '["threefa-vault-v1"]'::jsonb,
    100,
    699052
)
ON CONFLICT (app_id) DO UPDATE SET
    allowed_namespaces = EXCLUDED.allowed_namespaces,
    max_batch_size = EXCLUDED.max_batch_size,
    max_ciphertext_base64_length = EXCLUDED.max_ciphertext_base64_length,
    updated_at = now();

CREATE TABLE IF NOT EXISTS cliptown.app_vault_mutations (
    server_sequence BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES cliptown.app_vault_applications(app_id) ON DELETE RESTRICT,
    mutation_id TEXT NOT NULL CHECK (
        char_length(mutation_id) BETWEEN 1 AND 128
        AND mutation_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    namespace TEXT NOT NULL CHECK (
        char_length(namespace) BETWEEN 1 AND 128
        AND namespace ~ '^[A-Za-z0-9._:-]+$'
    ),
    opaque_record_id TEXT NOT NULL CHECK (
        char_length(opaque_record_id) BETWEEN 16 AND 128
        AND opaque_record_id ~ '^[A-Za-z0-9_-]+$'
    ),
    payload_algorithm TEXT CHECK (
        payload_algorithm IS NULL OR payload_algorithm IN (
            'xchacha20poly1305-v1', 'aes-256-gcm-v1'
        )
    ),
    payload_nonce_base64 TEXT CHECK (
        payload_nonce_base64 IS NULL OR octet_length(payload_nonce_base64) BETWEEN 16 AND 64
    ),
    payload_ciphertext_base64 TEXT CHECK (
        payload_ciphertext_base64 IS NULL
        OR octet_length(payload_ciphertext_base64) BETWEEN 1 AND 699052
    ),
    payload_associated_data_hash_base64 TEXT CHECK (
        payload_associated_data_hash_base64 IS NULL
        OR octet_length(payload_associated_data_hash_base64) BETWEEN 43 AND 44
    ),
    payload_key_id TEXT CHECK (
        payload_key_id IS NULL OR char_length(payload_key_id) BETWEEN 1 AND 128
    ),
    deleted BOOLEAN NOT NULL,
    source_device_id UUID NOT NULL,
    logical_clock BIGINT NOT NULL CHECK (logical_clock >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at >= created_at),
    device_signature_base64 TEXT NOT NULL CHECK (
        octet_length(device_signature_base64) BETWEEN 43 AND 684
    ),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, app_id, mutation_id),
    UNIQUE (user_id, app_id, mutation_id, server_sequence),
    CONSTRAINT app_vault_mutations_head_identity_unique UNIQUE (
        user_id,
        app_id,
        namespace,
        opaque_record_id,
        mutation_id,
        server_sequence,
        logical_clock,
        source_device_id,
        updated_at
    ),
    CONSTRAINT app_vault_mutations_source_device_user_fk
        FOREIGN KEY (user_id, source_device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE RESTRICT,
    CONSTRAINT app_vault_mutations_live_or_tombstone CHECK (
        (
            deleted
            AND payload_algorithm IS NULL
            AND payload_nonce_base64 IS NULL
            AND payload_ciphertext_base64 IS NULL
            AND payload_associated_data_hash_base64 IS NULL
            AND payload_key_id IS NULL
        )
        OR (
            NOT deleted
            AND payload_algorithm IS NOT NULL
            AND payload_nonce_base64 IS NOT NULL
            AND payload_ciphertext_base64 IS NOT NULL
            AND payload_associated_data_hash_base64 IS NOT NULL
            AND payload_key_id IS NOT NULL
        )
    ),
    CONSTRAINT app_vault_mutations_future_skew CHECK (
        created_at <= received_at + INTERVAL '5 minutes'
        AND updated_at <= received_at + INTERVAL '5 minutes'
    )
);
CREATE INDEX IF NOT EXISTS app_vault_mutations_cursor_idx
    ON cliptown.app_vault_mutations (user_id, app_id, server_sequence);
CREATE INDEX IF NOT EXISTS app_vault_mutations_record_clock_idx
    ON cliptown.app_vault_mutations (
        user_id, app_id, namespace, opaque_record_id, logical_clock, source_device_id
    );

CREATE TABLE IF NOT EXISTS cliptown.app_vault_record_heads (
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES cliptown.app_vault_applications(app_id) ON DELETE RESTRICT,
    namespace TEXT NOT NULL,
    opaque_record_id TEXT NOT NULL,
    mutation_id TEXT NOT NULL,
    server_sequence BIGINT NOT NULL,
    logical_clock BIGINT NOT NULL CHECK (logical_clock >= 0),
    source_device_id UUID NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, app_id, namespace, opaque_record_id),
    CONSTRAINT app_vault_record_heads_mutation_identity_fk
        FOREIGN KEY (
            user_id,
            app_id,
            namespace,
            opaque_record_id,
            mutation_id,
            server_sequence,
            logical_clock,
            source_device_id,
            updated_at
        ) REFERENCES cliptown.app_vault_mutations (
            user_id,
            app_id,
            namespace,
            opaque_record_id,
            mutation_id,
            server_sequence,
            logical_clock,
            source_device_id,
            updated_at
        ) ON DELETE CASCADE,
    CONSTRAINT app_vault_record_heads_source_device_user_fk
        FOREIGN KEY (user_id, source_device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS cliptown.external_step_up_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    initiating_device_id UUID NOT NULL,
    audience TEXT NOT NULL CHECK (audience = 'cliptown'),
    action TEXT NOT NULL CHECK (action IN (
        'enroll_device', 'revoke_device', 'update_security_settings',
        'change_recovery_channel', 'export_app_vault', 'recover_account'
    )),
    method TEXT NOT NULL CHECK (method IN ('POST', 'PUT', 'PATCH', 'DELETE')),
    normalized_route TEXT NOT NULL CHECK (
        char_length(normalized_route) BETWEEN 1 AND 256
        AND normalized_route LIKE '/%'
        AND normalized_route NOT LIKE '%?%'
        AND normalized_route NOT LIKE '%#%'
        AND normalized_route NOT LIKE '%//%'
        AND normalized_route !~ '(^|/)\.{1,2}($|/)'
    ),
    target_resource_id TEXT CHECK (
        target_resource_id IS NULL OR (
            char_length(target_resource_id) BETWEEN 1 AND 128
            AND target_resource_id ~ '^[A-Za-z0-9._:-]+$'
        )
    ),
    request_body_sha256_base64 TEXT NOT NULL CHECK (
        octet_length(request_body_sha256_base64) BETWEEN 43 AND 44
        AND request_body_sha256_base64 ~ '^[A-Za-z0-9+/_-]{43}=?$'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '5 minutes'
    ),
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    consumed_proof_id TEXT,
    UNIQUE (user_id, id),
    CONSTRAINT external_step_up_challenges_device_user_fk
        FOREIGN KEY (user_id, initiating_device_id)
        REFERENCES cliptown.devices(user_id, id) ON DELETE CASCADE,
    CONSTRAINT external_step_up_challenges_terminal_state CHECK (
        consumed_at IS NULL OR invalidated_at IS NULL
    ),
    CONSTRAINT external_step_up_challenges_consumption_consistent CHECK (
        (consumed_at IS NULL AND consumed_proof_id IS NULL)
        OR (consumed_at IS NOT NULL AND consumed_proof_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS external_step_up_challenges_active_idx
    ON cliptown.external_step_up_challenges (
        user_id, initiating_device_id, expires_at
    )
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE IF NOT EXISTS cliptown.external_step_up_proofs (
    proof_id TEXT PRIMARY KEY CHECK (
        char_length(proof_id) BETWEEN 1 AND 128
        AND proof_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    user_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    challenge_id UUID NOT NULL,
    issuer TEXT NOT NULL CHECK (issuer = 'https://3fa.app'),
    subject TEXT NOT NULL CHECK (subject = user_id::text),
    audience TEXT NOT NULL CHECK (audience = 'cliptown'),
    approving_external_device_id TEXT NOT NULL CHECK (
        char_length(approving_external_device_id) BETWEEN 1 AND 128
        AND approving_external_device_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    action TEXT NOT NULL CHECK (action IN (
        'enroll_device', 'revoke_device', 'update_security_settings',
        'change_recovery_channel', 'export_app_vault', 'recover_account'
    )),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + INTERVAL '5 minutes'
    ),
    signing_key_id TEXT NOT NULL CHECK (char_length(signing_key_id) BETWEEN 1 AND 128),
    signature_base64 TEXT NOT NULL CHECK (octet_length(signature_base64) BETWEEN 43 AND 684),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ,
    UNIQUE (challenge_id),
    CONSTRAINT external_step_up_proofs_challenge_user_fk
        FOREIGN KEY (user_id, challenge_id)
        REFERENCES cliptown.external_step_up_challenges(user_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS external_step_up_proofs_active_idx
    ON cliptown.external_step_up_proofs (user_id, challenge_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE OR REPLACE FUNCTION cliptown.consume_external_step_up(
    p_user_id UUID,
    p_initiating_device_id UUID,
    p_challenge_id UUID,
    p_proof_id TEXT,
    p_action TEXT,
    p_method TEXT,
    p_normalized_route TEXT,
    p_target_resource_id TEXT,
    p_request_body_sha256_base64 TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, cliptown
AS $$
DECLARE
    v_now TIMESTAMPTZ := transaction_timestamp();
BEGIN
    IF p_user_id IS DISTINCT FROM cliptown.current_user_id()
        OR p_initiating_device_id IS DISTINCT FROM cliptown.current_device_id()
    THEN
        RETURN false;
    END IF;

    PERFORM 1
    FROM cliptown.external_step_up_challenges AS challenge
    JOIN cliptown.external_step_up_proofs AS proof
        ON proof.user_id = challenge.user_id
        AND proof.challenge_id = challenge.id
    JOIN cliptown.devices AS device
        ON device.user_id = challenge.user_id
        AND device.id = challenge.initiating_device_id
    WHERE challenge.user_id = p_user_id
      AND challenge.initiating_device_id = p_initiating_device_id
      AND challenge.id = p_challenge_id
      AND challenge.action = p_action
      AND challenge.method = p_method
      AND challenge.normalized_route = p_normalized_route
      AND challenge.target_resource_id IS NOT DISTINCT FROM p_target_resource_id
      AND challenge.request_body_sha256_base64 = p_request_body_sha256_base64
      AND challenge.audience = 'cliptown'
      AND challenge.consumed_at IS NULL
      AND challenge.invalidated_at IS NULL
      AND challenge.created_at <= v_now + INTERVAL '5 minutes'
      AND challenge.expires_at > v_now
      AND device.lifecycle_state = 'active'
      AND proof.proof_id = p_proof_id
      AND proof.issuer = 'https://3fa.app'
      AND proof.subject = p_user_id::text
      AND proof.audience = challenge.audience
      AND proof.action = challenge.action
      AND proof.issued_at >= challenge.created_at - INTERVAL '5 minutes'
      AND proof.issued_at <= v_now + INTERVAL '5 minutes'
      AND proof.expires_at <= challenge.expires_at
      AND proof.expires_at > v_now
      AND proof.verified_at <= v_now
      AND proof.consumed_at IS NULL
    FOR UPDATE OF challenge, proof;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    UPDATE cliptown.external_step_up_challenges
    SET consumed_at = v_now,
        consumed_proof_id = p_proof_id
    WHERE id = p_challenge_id
      AND user_id = p_user_id
      AND consumed_at IS NULL
      AND invalidated_at IS NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'external step-up challenge consumption invariant violated';
    END IF;

    UPDATE cliptown.external_step_up_proofs
    SET consumed_at = v_now
    WHERE proof_id = p_proof_id
      AND user_id = p_user_id
      AND challenge_id = p_challenge_id
      AND consumed_at IS NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'external step-up proof consumption invariant violated';
    END IF;

    RETURN true;
END;
$$;

ALTER TABLE cliptown.device_verification_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.app_vault_mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.app_vault_record_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.external_step_up_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.external_step_up_proofs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_verification_keys_active_device_select
    ON cliptown.device_verification_keys;
CREATE POLICY device_verification_keys_active_device_select
    ON cliptown.device_verification_keys
    FOR SELECT
    USING (
        user_id = cliptown.current_user_id()
        AND EXISTS (
            SELECT 1
            FROM cliptown.devices AS current_device
            WHERE current_device.user_id = cliptown.current_user_id()
              AND current_device.id = cliptown.current_device_id()
              AND current_device.lifecycle_state = 'active'
        )
    );

DROP POLICY IF EXISTS app_vault_mutations_active_device_select
    ON cliptown.app_vault_mutations;
CREATE POLICY app_vault_mutations_active_device_select
    ON cliptown.app_vault_mutations
    FOR SELECT
    USING (
        user_id = cliptown.current_user_id()
        AND EXISTS (
            SELECT 1
            FROM cliptown.devices AS current_device
            WHERE current_device.user_id = cliptown.current_user_id()
              AND current_device.id = cliptown.current_device_id()
              AND current_device.lifecycle_state = 'active'
        )
    );

DROP POLICY IF EXISTS app_vault_mutations_active_device_insert
    ON cliptown.app_vault_mutations;
CREATE POLICY app_vault_mutations_active_device_insert
    ON cliptown.app_vault_mutations
    FOR INSERT
    WITH CHECK (
        user_id = cliptown.current_user_id()
        AND source_device_id = cliptown.current_device_id()
        AND EXISTS (
            SELECT 1
            FROM cliptown.devices AS current_device
            WHERE current_device.user_id = cliptown.current_user_id()
              AND current_device.id = cliptown.current_device_id()
              AND current_device.lifecycle_state = 'active'
        )
        AND cliptown.app_vault_application_allows(app_id, namespace)
    );

DROP POLICY IF EXISTS app_vault_record_heads_active_device_select
    ON cliptown.app_vault_record_heads;
CREATE POLICY app_vault_record_heads_active_device_select
    ON cliptown.app_vault_record_heads
    FOR SELECT
    USING (
        user_id = cliptown.current_user_id()
        AND EXISTS (
            SELECT 1
            FROM cliptown.devices AS current_device
            WHERE current_device.user_id = cliptown.current_user_id()
              AND current_device.id = cliptown.current_device_id()
              AND current_device.lifecycle_state = 'active'
        )
    );

DROP POLICY IF EXISTS external_step_up_challenges_initiating_device_select
    ON cliptown.external_step_up_challenges;
CREATE POLICY external_step_up_challenges_initiating_device_select
    ON cliptown.external_step_up_challenges
    FOR SELECT
    USING (
        user_id = cliptown.current_user_id()
        AND initiating_device_id = cliptown.current_device_id()
        AND EXISTS (
            SELECT 1
            FROM cliptown.devices AS current_device
            WHERE current_device.user_id = cliptown.current_user_id()
              AND current_device.id = cliptown.current_device_id()
              AND current_device.lifecycle_state = 'active'
        )
    );

REVOKE ALL ON TABLE cliptown.device_verification_keys FROM PUBLIC;
REVOKE ALL ON TABLE cliptown.app_vault_applications FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cliptown.app_vault_application_allows(TEXT, TEXT) TO PUBLIC;
REVOKE ALL ON TABLE cliptown.app_vault_mutations FROM PUBLIC;
REVOKE ALL ON TABLE cliptown.app_vault_record_heads FROM PUBLIC;
REVOKE ALL ON TABLE cliptown.external_step_up_challenges FROM PUBLIC;
REVOKE ALL ON TABLE cliptown.external_step_up_proofs FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA cliptown FROM PUBLIC;
REVOKE ALL ON FUNCTION cliptown.consume_external_step_up(
    UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC;

-- END DEN-44 APP VAULT AND EXTERNAL STEP-UP

-- BEGIN DEN-1578 MEMEBANK TRANSFER API
-- Subject-owned encrypted transfer queue for the versioned API boundary.

CREATE TABLE IF NOT EXISTS cliptown.memebank_transfers (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    contract_version SMALLINT NOT NULL CHECK (contract_version = 1),
    direction TEXT NOT NULL CHECK (
        direction IN ('memebank_to_cliptown', 'cliptown_to_memebank')
    ),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN (
            'pending', 'acknowledged', 'ignored', 'rejected', 'expired', 'cancelled'
        )
    ),
    source_item_id TEXT NOT NULL CHECK (
        char_length(source_item_id) BETWEEN 1 AND 128
        AND source_item_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    media_type TEXT NOT NULL CHECK (
        char_length(media_type) BETWEEN 3 AND 128
        AND media_type ~ '^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$'
    ),
    content_sha256_base64url TEXT NOT NULL CHECK (
        char_length(content_sha256_base64url) BETWEEN 43 AND 44
        AND content_sha256_base64url ~ '^[A-Za-z0-9_-]{43}=?$'
    ),
    content_length BIGINT NOT NULL CHECK (content_length BETWEEN 0 AND 16777216),
    payload_algorithm TEXT NOT NULL CHECK (
        payload_algorithm IN ('xchacha20poly1305-v1', 'aes-256-gcm-v1')
    ),
    payload_nonce_base64 TEXT NOT NULL CHECK (
        char_length(payload_nonce_base64) BETWEEN 16 AND 128
    ),
    payload_ciphertext_base64 TEXT NOT NULL CHECK (
        octet_length(payload_ciphertext_base64) BETWEEN 1 AND 22369624
    ),
    payload_associated_data_hash_base64 TEXT CHECK (
        octet_length(payload_associated_data_hash_base64) <= 128
    ),
    payload_key_id TEXT NOT NULL CHECK (
        char_length(payload_key_id) BETWEEN 1 AND 128
        AND payload_key_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    metadata_algorithm TEXT CHECK (
        metadata_algorithm IN ('xchacha20poly1305-v1', 'aes-256-gcm-v1')
    ),
    metadata_nonce_base64 TEXT CHECK (
        char_length(metadata_nonce_base64) BETWEEN 16 AND 128
    ),
    metadata_ciphertext_base64 TEXT CHECK (
        octet_length(metadata_ciphertext_base64) BETWEEN 1 AND 22369624
    ),
    metadata_associated_data_hash_base64 TEXT CHECK (
        octet_length(metadata_associated_data_hash_base64) <= 128
    ),
    metadata_key_id TEXT CHECK (
        char_length(metadata_key_id) BETWEEN 1 AND 128
        AND metadata_key_id ~ '^[A-Za-z0-9._:-]+$'
    ),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    CONSTRAINT memebank_transfer_retention CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '30 days'
    ),
    CONSTRAINT memebank_transfer_metadata_complete CHECK (
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
    CONSTRAINT memebank_transfer_terminal_timestamps CHECK (
        (
            state IN ('acknowledged', 'ignored', 'rejected')
            AND acknowledged_at IS NOT NULL
            AND cancelled_at IS NULL
        )
        OR (
            state = 'cancelled'
            AND acknowledged_at IS NULL
            AND cancelled_at IS NOT NULL
        )
        OR (
            state IN ('pending', 'expired')
            AND acknowledged_at IS NULL
            AND cancelled_at IS NULL
        )
    )
);
CREATE INDEX IF NOT EXISTS memebank_transfers_subject_state_created_idx
    ON cliptown.memebank_transfers (subject_id, state, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS memebank_transfers_subject_expiry_idx
    ON cliptown.memebank_transfers (subject_id, expires_at, id);

CREATE TABLE IF NOT EXISTS cliptown.memebank_transfer_idempotency (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id UUID NOT NULL REFERENCES cliptown.accounts(user_id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 16 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9._:-]+$'
    ),
    operation TEXT NOT NULL CHECK (operation IN ('create', 'acknowledge')),
    normalized_route TEXT NOT NULL CHECK (
        char_length(normalized_route) BETWEEN 1 AND 256
        AND normalized_route LIKE '/%'
        AND normalized_route NOT LIKE '%?%'
        AND normalized_route NOT LIKE '%#%'
        AND normalized_route NOT LIKE '%//%'
    ),
    request_digest_base64url TEXT NOT NULL CHECK (
        char_length(request_digest_base64url) BETWEEN 43 AND 44
        AND request_digest_base64url ~ '^[A-Za-z0-9_-]{43}=?$'
    ),
    transfer_id UUID REFERENCES cliptown.memebank_transfers(id) ON DELETE CASCADE,
    response_state TEXT CHECK (
        response_state IN (
            'pending', 'acknowledged', 'ignored', 'rejected', 'expired', 'cancelled'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '30 days'
    ),
    UNIQUE (subject_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS memebank_transfer_idempotency_expiry_idx
    ON cliptown.memebank_transfer_idempotency (expires_at);

ALTER TABLE cliptown.memebank_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE cliptown.memebank_transfer_idempotency ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS memebank_transfers_owner_policy ON cliptown.memebank_transfers;
CREATE POLICY memebank_transfers_owner_policy ON cliptown.memebank_transfers
    USING (subject_id = cliptown.current_user_id())
    WITH CHECK (subject_id = cliptown.current_user_id());

DROP POLICY IF EXISTS memebank_transfer_idempotency_owner_policy
    ON cliptown.memebank_transfer_idempotency;
CREATE POLICY memebank_transfer_idempotency_owner_policy
    ON cliptown.memebank_transfer_idempotency
    USING (subject_id = cliptown.current_user_id())
    WITH CHECK (subject_id = cliptown.current_user_id());

REVOKE ALL ON cliptown.memebank_transfers FROM PUBLIC;
REVOKE ALL ON cliptown.memebank_transfer_idempotency FROM PUBLIC;
-- END DEN-1578 MEMEBANK TRANSFER API
