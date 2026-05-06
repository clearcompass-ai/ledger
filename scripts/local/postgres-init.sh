#!/bin/bash
# Postgres init for the dev + integration topologies. Runs once on
# the first boot of the postgres container (mounted at
# /docker-entrypoint-initdb.d/).
#
# Creates the additional database this 2-node topology needs:
#   attesta_node_a   (default; owned by ledger-node-a; created
#                     by the postgres image from POSTGRES_DB)
#   attesta_node_b   (owned by ledger-node-b; created here)
#
# Domain-specific demos that need additional databases (e.g.,
# the judicial-network walkthrough's court-tools / provider-tools
# binaries) live in their own repos and create those databases
# from their own init scripts.
#
# Idempotent: subsequent boots skip the init dir per upstream docker
# entrypoint contract.

set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<-EOSQL
    CREATE DATABASE attesta_node_b;
    GRANT ALL PRIVILEGES ON DATABASE attesta_node_b TO ${POSTGRES_USER};
EOSQL

echo "postgres-init: created attesta_node_b database"
