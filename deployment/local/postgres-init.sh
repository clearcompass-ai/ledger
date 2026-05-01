#!/bin/bash
# Postgres init for the dev topology. Runs once on the first boot of
# the postgres container (mounted at /docker-entrypoint-initdb.d/).
#
# The default POSTGRES_DB env in compose creates `ortholog_davidson`.
# This script adds the second database (ortholog_coa) so the COA
# operator has its own schema namespace.
#
# Idempotent: subsequent boots skip the init dir per upstream docker
# entrypoint contract.

set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<-EOSQL
    CREATE DATABASE ortholog_coa;
    GRANT ALL PRIVILEGES ON DATABASE ortholog_coa TO ${POSTGRES_USER};
EOSQL

echo "postgres-init: created ortholog_coa database"
