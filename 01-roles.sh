#!/bin/bash
# Runs once at first DB start. The app connects as a LEAST-PRIVILEGE role that can append to
# audit_events but can never UPDATE / DELETE / TRUNCATE it, even if the gateway is compromised.
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE bayora_app LOGIN PASSWORD '${BAYORA_APP_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO bayora_app;
GRANT USAGE, CREATE ON SCHEMA public TO bayora_app;

-- Owned by the superuser so bayora_app cannot alter or drop it or its trigger.
CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY, ts VARCHAR(40) NOT NULL, actor VARCHAR(64) NOT NULL, role VARCHAR(16) NOT NULL,
  event_type VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL, source_ip VARCHAR(64) NOT NULL,
  details TEXT NOT NULL, prev_hash VARCHAR(64) NOT NULL, hash VARCHAR(64) NOT NULL, sig VARCHAR(64) NOT NULL);
GRANT SELECT, INSERT ON audit_events TO bayora_app;

CREATE FUNCTION bayora_audit_immutable() RETURNS trigger AS \$\$
BEGIN RAISE EXCEPTION 'audit_events is append-only'; END; \$\$ LANGUAGE plpgsql;
CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION bayora_audit_immutable();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION bayora_audit_immutable();
SQL
