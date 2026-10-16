-- PostgreSQL baseline 0003: rule packages and SBOM index.
-- Objects and scan results are stored outside PostgreSQL; store only
-- immutable identity, version and object URI/hash metadata in these tables.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0002_scanning') THEN
        RAISE EXCEPTION 'Apply 0002_scanning.sql before 0003_rules_sbom.sql';
    END IF;
END
$$;

CREATE TABLE rule_bundles (
    version TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_rule_version_nonempty CHECK (length(btrim(version)) > 0),
    CONSTRAINT ck_rule_channel_nonempty CHECK (length(btrim(channel)) > 0),
    CONSTRAINT ck_manifest_hash_nonempty CHECK (length(btrim(manifest_sha256)) > 0)
);
CREATE INDEX idx_rule_bundles_channel_published
    ON rule_bundles(channel, published_at DESC);

-- Store the pointer and hash, never binary SBOM content or credentials.
-- Keep rule_version as plain TEXT: old SBOM references may outlive physical
-- rule package retention; deletion policies are enforced in Server/Updater.
CREATE TABLE artifact_sboms (
    manifest_digest TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    sbom_uri TEXT NOT NULL,
    sbom_sha256 TEXT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (manifest_digest, rule_version, engine_version)
);
CREATE INDEX idx_artifact_sboms_repo_scanned
    ON artifact_sboms(repo_name, scanned_at DESC);
CREATE INDEX idx_artifact_sboms_manifest_digest
    ON artifact_sboms(manifest_digest);

-- No initial rule bundle, signing key, Node token or sample SBOM is seeded.
-- Publishing a manifest or activating CURRENT remains an explicit,
-- authenticated, verified Server/Updater operation.
INSERT INTO schema_migrations(version) VALUES ('0003_rules_sbom');
COMMIT;
