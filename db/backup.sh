#!/bin/sh
# Nightly full backup of the uniwatch database (pg_dump custom format) into /backups, keeping BACKUP_KEEP_DAYS days.
# Each run is recorded in audit_log (action db_backup) so a failed night is visible in the app.
# Restore (tested 2026-10-07: every table identical as of the dump time):
#   createdb ... ; CREATE EXTENSION timescaledb; SELECT timescaledb_pre_restore();
#   pg_restore -d <db> <file> ; SELECT timescaledb_post_restore();
set -u
AT="${BACKUP_AT_UTC:-18:30}"          # 02:30 Hong Kong time
KEEP="${BACKUP_KEEP_DAYS:-14}"
DB="${DB_NAME:-uniwatch}"
export PGHOST=db PGUSER="${POSTGRES_USER:-postgres}" PGPASSWORD="${POSTGRES_PASSWORD:?}"

record() {  # $1 = true|false, $2 = JSON details
  psql -d "$DB" -qc "INSERT INTO audit_log (username, action, success, details) VALUES ('backup', 'db_backup', $1, '$2')" \
    || echo "could not record the backup result"
}

run_backup() {
  f="/backups/${DB}-$(date -u +%Y%m%dT%H%M).dump"
  start=$(date +%s)
  if pg_dump -Fc -d "$DB" -f "$f.part" 2>/tmp/backup.err; then
    mv "$f.part" "$f"
    size=$(stat -c %s "$f")
    echo "$(date -u +%FT%TZ) backup ok: $f ($size bytes, $(( $(date +%s) - start )) s)"
    record true "{\"file\": \"$(basename "$f")\", \"bytes\": $size}"
  else
    rm -f "$f.part"
    err=$(grep -v '^pg_dump: \(warning\|detail\|hint\)' /tmp/backup.err | head -c 300 | tr -d "'\"\\\\" | tr '\n' ' ')
    echo "$(date -u +%FT%TZ) backup FAILED: $err"
    record false "{\"error\": \"$err\"}"
  fi
  find /backups -name "${DB}-*.dump" -mtime +"$KEEP" -print -delete
}

[ "${1:-}" = "now" ] && { run_backup; exit 0; }
echo "backup service: daily at $AT UTC, keeping $KEEP days"
while true; do
  if [ "$(date -u +%H:%M)" = "$AT" ]; then
    run_backup
    sleep 61
  fi
  sleep 20
done
