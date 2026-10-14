#!/usr/bin/env sh
# One-off (idempotent): create the least-privilege web role on an existing installation.
# Fresh installs get it from db/init/00-roles.sh. Needs the database superuser, so it runs inside the db
# container. Adds DB_WEB_PASSWORD to .env if missing.
set -eu
cd "$(dirname "$0")/.."
if ! grep -q '^DB_WEB_PASSWORD=' .env; then
  umask 077
  printf 'DB_WEB_USER=uniwatch_web\nDB_WEB_PASSWORD=%s\n' "$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)" >> .env
  echo "added DB_WEB_USER/DB_WEB_PASSWORD to .env"
fi
WEB_USER=$(grep '^DB_WEB_USER=' .env | cut -d= -f2-)
WEB_PW=$(grep '^DB_WEB_PASSWORD=' .env | cut -d= -f2-)
DB=$(grep '^DB_NAME=' .env | cut -d= -f2-)
docker compose exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -v web="$1" -v pw="$2" -v db="$3" -v testdb="$3_test"' _ "$WEB_USER" "$WEB_PW" "$DB" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', :'web', :'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'web') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'web', :'pw') \gexec
ALTER ROLE :"web" SET search_path = scoped, public;
GRANT CONNECT ON DATABASE :"db" TO :"web";
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'testdb', :'web') WHERE EXISTS (SELECT 1 FROM pg_database WHERE datname = :'testdb') \gexec
SQL
echo "web role ready"
