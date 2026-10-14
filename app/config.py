from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    """All configuration comes from the environment (.env via compose). No secrets in code."""

    model_config = SettingsConfigDict(extra="ignore")

    app_name: str = "Uniwatch"

    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "uniwatch"
    db_app_user: str = "uniwatch_app"
    db_app_password: str
    db_web_user: str = "uniwatch_web"         # least-privilege role for the web UI (RLS + scoped views)
    db_web_password: str = ""
    db_owner_user: str = "uniwatch_owner"
    db_owner_password: str = ""

    secret_key: str
    cookie_secure: bool = True
    session_max_hours: int = 12
    session_idle_minutes: int = 60
    login_max_failures: int = 10
    login_window_minutes: int = 15
    mfa_max_failures: int = 5
    totp_issuer: str = "Uniwatch"
    default_timezone: str = "Asia/Hong_Kong"

    # --- receiver (Phase 2) ---
    receiver_bind: str = "0.0.0.0"
    receiver_udp_port: int = 5141
    receiver_tcp_port: int = 5141
    # Additional ports listened on for both UDP and TCP, comma-separated (e.g. "514").
    receiver_extra_ports: str = "514"
    # NetFlow/IPFIX: capture only (no parser until real UniFi records have been seen). 0 disables.
    # UniFi Site Manager (api.ui.com) read-only API key; empty = disabled.
    unifi_site_manager_api_key: str = ""
    sitemanager_interval_s: int = 300
    alert_subject_prefix: str = "UniFi Alert"     # alert e-mail subject: "<prefix>: <what> at <client>"
    firewall_interval_s: int = 3600       # firewall policy snapshots (Rule & Policy report)
    clients_interval_s: int = 600         # client names from Site Manager consoles
    protect_interval_s: int = 300         # CCTV access log (UniFi Protect) from Site Manager consoles
    config_interval_s: int = 10800        # configuration backups of the UniFi consoles (new version only when changed)
    fw_backup_interval_s: int = 21600     # local copies of the consoles' own backup files (.unf): catch-up check ...
    fw_backup_weekly: str = "sun 01:30 Asia/Hong_Kong"   # ... plus a run right after the consoles' weekly backup (Sun 01:00)
    fw_backup_dir: str = "/srv/fw-backups"
    fw_backup_keep: int = 12              # newest backup files always kept per console ...
    fw_backup_keep_days: int = 92         # ... and every backup file of the last 3 months
    packs_dir: str = "/srv/packs"         # uploaded report packs and their licences (app/packs.py)
    # Whose report packs this installation accepts (Ed25519 public key, base64); empty = report packs off.
    pack_public_key: str = "6Fwl9TzPJL6aWhjcDZp3ShW78iqotfVvx0tO2CMtHo4="
    platform_client_slug: str = "nwhk"    # log server health alerts are filed under this client (the MSP itself)
    # Base URL people use to open the web UI (links in alert e-mails / Teams); empty = no links.
    public_url: str = ""
    receiver_netflow_port: int = 2055
    netflow_capture_dir: str = "/srv/netflow-capture"
    netflow_capture_max: int = 300              # datagrams kept per sender; later ones are only counted
    receiver_max_message_bytes: int = 16384     # longer lines are truncated and flagged
    receiver_rate_per_source: float = 2000.0    # sustained messages/second per source IP
    receiver_burst_per_source: int = 20000
    receiver_queue_max: int = 200000            # in-memory buffer while the DB is slow/unavailable
    receiver_batch_max: int = 5000
    receiver_flush_seconds: float = 0.5
    receiver_device_refresh_seconds: float = 15.0
    receiver_tcp_max_connections: int = 256
    receiver_tcp_idle_seconds: float = 600.0
    receiver_udp_rcvbuf: int = 16 * 1024 * 1024
    receiver_heartbeat_file: str = "/tmp/receiver-heartbeat"

    # --- reports (Phase 8) ---
    reports_dir: str = "/srv/reports"
    smtp_host: str = ""                 # empty = e-mail delivery disabled
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True

    initial_admin_username: str = "admin"
    initial_admin_password: str = ""

    def receiver_extra_port_list(self) -> list[int]:
        return [int(p) for p in self.receiver_extra_ports.replace(" ", "").split(",") if p]

    def db_conninfo(self) -> str:
        """libpq conninfo for raw psycopg connections (the receiver uses COPY directly)."""
        from psycopg.conninfo import make_conninfo

        return make_conninfo(
            host=self.db_host, port=self.db_port, dbname=self.db_name,
            user=self.db_app_user, password=self.db_app_password,
            options="-c timezone=UTC", application_name="uniwatch-receiver",
        )

    def db_url(self, *, owner: bool = False, web: bool = False) -> URL:
        """App role by default; the web role for the UI; the schema-owner role only for migrations."""
        user, pw = ((self.db_owner_user, self.db_owner_password) if owner else
                    (self.db_web_user, self.db_web_password) if web else (self.db_app_user, self.db_app_password))
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=pw,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
