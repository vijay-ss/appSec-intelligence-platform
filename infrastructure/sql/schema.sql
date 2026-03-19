-- AppSec Intelligence Platform — PostgreSQL Schema
-- Run automatically via docker-entrypoint-initdb.d on first container start.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Core vulnerability tables ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id                VARCHAR(20)   PRIMARY KEY,
    cvss_score            DECIMAL(3,1),
    severity_tier         VARCHAR(10),
    description           TEXT,
    affected_package      VARCHAR(200),
    ecosystem             VARCHAR(20),
    affected_version_range VARCHAR(200),
    safe_version          VARCHAR(100),
    cwe_id                VARCHAR(20),
    published_at          TIMESTAMPTZ,
    source                VARCHAR(10),  -- nvd | osv
    created_at            TIMESTAMPTZ   DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerability_matches (
    match_id        UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id          VARCHAR(20)   REFERENCES vulnerabilities(cve_id),
    service_id      VARCHAR(200),
    matched_version VARCHAR(100),
    blast_radius    VARCHAR(10),
    status          VARCHAR(20)   DEFAULT 'open',  -- open | in_progress | resolved | accepted_risk
    sla_deadline    TIMESTAMPTZ,
    assigned_to     VARCHAR(100),
    assigned_team   VARCHAR(100),
    detected_at     TIMESTAMPTZ   DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS triage_reports (
    report_id               UUID        PRIMARY KEY,
    match_id                UUID        REFERENCES vulnerability_matches(match_id),
    exploitability          VARCHAR(20),
    exploitability_rationale TEXT,
    blast_radius_rationale  TEXT,
    remediation_action      TEXT,
    is_breaking_change      BOOLEAN     DEFAULT FALSE,
    estimated_effort_hours  DECIMAL(4,1),
    confidence_score        DECIMAL(3,2),
    sources_cited           JSONB,
    llm_provider            VARCHAR(100),
    generated_at            TIMESTAMPTZ DEFAULT NOW()
);

-- ── Service registry ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS service_registry (
    service_id          VARCHAR(200) PRIMARY KEY,
    team                VARCHAR(100),
    ecosystem           VARCHAR(20),
    repo                VARCHAR(200),
    is_customer_facing  BOOLEAN      DEFAULT FALSE,
    pci_scope           BOOLEAN      DEFAULT FALSE,
    hipaa_scope         BOOLEAN      DEFAULT FALSE,
    soc2_scope          BOOLEAN      DEFAULT FALSE,
    pii_handler         BOOLEAN      DEFAULT FALSE,
    description         TEXT,
    code_owners         JSONB
);

-- ── Flink dependency graph snapshots ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dep_graph_snapshots (
    snapshot_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id      VARCHAR(200),
    ecosystem       VARCHAR(20),
    dependencies    JSONB,      -- {package_name: pinned_version}
    snapshot_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dep_graph_service_id ON dep_graph_snapshots(service_id);
CREATE INDEX IF NOT EXISTS idx_dep_graph_snapshot_at ON dep_graph_snapshots(snapshot_at DESC);

-- ── Posture reports ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS posture_reports (
    report_id        UUID        PRIMARY KEY,
    generated_at     TIMESTAMPTZ DEFAULT NOW(),
    period_days      INTEGER,
    open_critical    INTEGER     DEFAULT 0,
    open_high        INTEGER     DEFAULT 0,
    open_medium      INTEGER     DEFAULT 0,
    open_low         INTEGER     DEFAULT 0,
    past_sla_count   INTEGER     DEFAULT 0,
    mttd_minutes     DECIMAL(8,2),
    mttr_days        DECIMAL(8,2),
    trend_direction  VARCHAR(20),
    executive_summary TEXT,
    compliance_gaps  JSONB,
    team_exposure    JSONB
);

-- ── Audit log ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    log_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  VARCHAR(50),
    entity_id   VARCHAR(200),
    actor       VARCHAR(100),
    action      TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Indexes ──────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_matches_status         ON vulnerability_matches(status);
CREATE INDEX IF NOT EXISTS idx_matches_service        ON vulnerability_matches(service_id);
CREATE INDEX IF NOT EXISTS idx_matches_cve            ON vulnerability_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_matches_team           ON vulnerability_matches(assigned_team);
CREATE INDEX IF NOT EXISTS idx_matches_sla            ON vulnerability_matches(sla_deadline);
CREATE INDEX IF NOT EXISTS idx_vulns_severity         ON vulnerabilities(severity_tier);
CREATE INDEX IF NOT EXISTS idx_audit_entity           ON audit_log(entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created          ON audit_log(created_at DESC);
