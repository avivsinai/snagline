-- PostgreSQL is the SSP semantic authority. Outbox rows are delivery work;
-- neither JetStream nor Buzz can issue receipts or change committed facts.

CREATE TABLE authority_revisions (
    revision BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE authority_cases (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    envelope_id TEXT NOT NULL,
    commitment TEXT NOT NULL,
    raw BYTEA NOT NULL,
    domain TEXT NOT NULL,
    issuer_edge_id TEXT NOT NULL,
    issuer_edge_generation BIGINT NOT NULL CHECK (issuer_edge_generation > 0),
    routing_epoch BIGINT NOT NULL CHECK (routing_epoch >= 0),
    registry_revision BIGINT NOT NULL CHECK (registry_revision >= 0),
    registry_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    commit_revision BIGINT NOT NULL REFERENCES authority_revisions(revision),
    committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, case_id),
    UNIQUE (tenant_id, envelope_id),
    UNIQUE (tenant_id, commitment),
    CHECK (octet_length(raw) > 0),
    CHECK (commitment ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (registry_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE authority_advice (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    envelope_id TEXT NOT NULL,
    case_commitment TEXT NOT NULL,
    commitment TEXT NOT NULL,
    raw BYTEA NOT NULL,
    routing_epoch BIGINT NOT NULL CHECK (routing_epoch >= 0),
    registry_revision BIGINT NOT NULL CHECK (registry_revision >= 0),
    registry_hash TEXT NOT NULL,
    target_edge_id TEXT NOT NULL,
    target_edge_generation BIGINT NOT NULL CHECK (target_edge_generation > 0),
    delivery_sequence BIGINT NOT NULL CHECK (delivery_sequence > 0),
    commit_revision BIGINT NOT NULL REFERENCES authority_revisions(revision),
    committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, case_id),
    UNIQUE (tenant_id, envelope_id),
    UNIQUE (tenant_id, commitment),
    FOREIGN KEY (tenant_id, case_id) REFERENCES authority_cases(tenant_id, case_id),
    CHECK (octet_length(raw) > 0),
    CHECK (case_commitment ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (commitment ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (registry_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE authority_edge_delivery_sequences (
    tenant_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    edge_generation BIGINT NOT NULL CHECK (edge_generation > 0),
    next_sequence BIGINT NOT NULL CHECK (next_sequence > 0),
    PRIMARY KEY (tenant_id, edge_id, edge_generation)
);

CREATE TABLE authority_edge_deliveries (
    tenant_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    edge_generation BIGINT NOT NULL CHECK (edge_generation > 0),
    delivery_sequence BIGINT NOT NULL CHECK (delivery_sequence > 0),
    delivery_kind TEXT NOT NULL CHECK (delivery_kind IN ('case', 'advice')),
    case_id TEXT NOT NULL,
    envelope_id TEXT NOT NULL,
    commitment TEXT NOT NULL,
    raw BYTEA NOT NULL,
    authority_revision BIGINT NOT NULL REFERENCES authority_revisions(revision),
    committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, edge_id, edge_generation, delivery_sequence),
    UNIQUE (tenant_id, envelope_id),
    CHECK (octet_length(raw) > 0),
    CHECK (commitment ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE authority_registry_heads (
    tenant_id TEXT PRIMARY KEY,
    latest_revision BIGINT NOT NULL CHECK (latest_revision > 0),
    latest_commitment TEXT NOT NULL CHECK (latest_commitment ~ '^sha256:[0-9a-f]{64}$'),
    routing_epoch BIGINT NOT NULL CHECK (routing_epoch >= 0),
    halted BOOLEAN NOT NULL DEFAULT FALSE,
    halt_reason TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE authority_edge_generation_high_water (
    tenant_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    principal_id TEXT NOT NULL CHECK (principal_id <> ''),
    highest_generation BIGINT NOT NULL CHECK (highest_generation > 0),
    last_seen_registry_revision BIGINT NOT NULL CHECK (last_seen_registry_revision > 0),
    PRIMARY KEY (tenant_id, edge_id)
);

CREATE TABLE authority_registries (
    tenant_id TEXT NOT NULL,
    registry_revision BIGINT NOT NULL CHECK (registry_revision > 0),
    envelope_id TEXT NOT NULL,
    commitment TEXT NOT NULL,
    raw BYTEA NOT NULL,
    routing_epoch BIGINT NOT NULL CHECK (routing_epoch >= 0),
    previous_commitment TEXT,
    commit_revision BIGINT NOT NULL REFERENCES authority_revisions(revision),
    committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, registry_revision),
    UNIQUE (tenant_id, envelope_id),
    UNIQUE (tenant_id, commitment),
    CHECK (octet_length(raw) > 0),
    CHECK (commitment ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (previous_commitment IS NULL OR previous_commitment ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE authority_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('case', 'advice', 'registry')),
    entity_id TEXT NOT NULL,
    commitment TEXT NOT NULL,
    authenticated_principal_id TEXT,
    authenticated_edge_id TEXT,
    decision TEXT,
    authority_revision BIGINT NOT NULL REFERENCES authority_revisions(revision),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (authority_revision),
    CHECK (commitment ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE authority_outbox (
    outbox_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('case', 'advice')),
    entity_id TEXT NOT NULL,
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('domain_dispatch', 'edge_delivery')),
    destination_key TEXT NOT NULL,
    raw BYTEA NOT NULL,
    authority_revision BIGINT NOT NULL REFERENCES authority_revisions(revision),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_owner TEXT,
    lease_token TEXT,
    lease_until TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    poisoned_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    UNIQUE (tenant_id, authority_revision, destination_kind, destination_key),
    CHECK (octet_length(raw) > 0),
    CHECK (
        (lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL)
        OR
        (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)
    )
);

CREATE INDEX authority_edge_deliveries_recovery_idx
    ON authority_edge_deliveries (tenant_id, edge_id, edge_generation, delivery_sequence);

CREATE INDEX authority_outbox_unpublished_idx
    ON authority_outbox (next_attempt_at, created_at, outbox_id)
    WHERE published_at IS NULL AND poisoned_at IS NULL;

CREATE INDEX authority_audit_tenant_recorded_idx
    ON authority_audit (tenant_id, recorded_at, audit_id);
