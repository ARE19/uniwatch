#!/bin/sh
# Runs once, on first initdb only (empty data dir).
# Creates the schema-owner role, the app role, the test database, and the TimescaleDB extension.
# Table-level grants live in the Alembic migrations so they apply to every database.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner="$DB_OWNER_USER" -v owner_pw="$DB_OWNER_PASSWORD" \
  -v app="$DB_APP_USER" -v app_pw="$DB_APP_PASSWORD" \
  -v web="$DB_WEB_USER" -v web_pw="$DB_WEB_PASSWORD" \
  -v db="$DB_NAME" -v testdb="${DB_NAME}_test" <<'SQL'
CREATE ROLE :"owner" LOGIN PASSWORD :'owner_pw';
CREATE ROLE :"app" LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE :"web" LOGIN PASSWORD :'web_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE :"web" SET search_path = scoped, public;
ALTER DATABASE :"db" OWNER TO :"owner";
CREATE DATABASE :"testdb" OWNER :"owner";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
REVOKE ALL ON DATABASE :"testdb" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"app";
GRANT CONNECT ON DATABASE :"testdb" TO :"app";
GRANT CONNECT ON DATABASE :"db" TO :"web";
GRANT CONNECT ON DATABASE :"testdb" TO :"web";
SQL

for d in "$DB_NAME" "${DB_NAME}_test"; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$d" \
    -c "CREATE EXTENSION IF NOT EXISTS timescaledb;" \
    -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
done
