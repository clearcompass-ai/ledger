#!/bin/bash
# Postgres init for the dev topology. Runs once on the first boot of
# the postgres container (mounted at /docker-entrypoint-initdb.d/).
#
# Creates the additional databases this dev topology needs:
#   attesta_davidson  (default; owned by the davidson ledger)
#   attesta_coa       (owned by the coa ledger)
#   court_tools        (owned by judicial-network's court-tools +
#                       provider-tools binaries)
#
# Idempotent: subsequent boots skip the init dir per upstream docker
# entrypoint contract.

set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<-EOSQL
    CREATE DATABASE attesta_coa;
    GRANT ALL PRIVILEGES ON DATABASE attesta_coa TO ${POSTGRES_USER};

    CREATE DATABASE court_tools;
    GRANT ALL PRIVILEGES ON DATABASE court_tools TO ${POSTGRES_USER};
EOSQL

echo "postgres-init: created attesta_coa + court_tools databases"
