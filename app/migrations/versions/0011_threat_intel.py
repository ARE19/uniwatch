"""Phase 13: threat-intel feeds, indicators (networks + domains), IoC alert rule type.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-06
"""
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

# Free feeds, formats verified 2026-10-06 (see app/intel/feeds.py). No API keys, no paid sources.
FEEDS = [
    ("abuse.ch Feodo Tracker (botnet C2)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ip_list"),
    ("abuse.ch URLhaus (malware hosts)", "https://urlhaus.abuse.ch/downloads/hostfile/", "hostfile"),
    ("Spamhaus DROP (hijacked netblocks)", "https://www.spamhaus.org/drop/drop_v4.json", "spamhaus_json"),
    ("Emerging Threats compromised IPs", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ip_list"),
    ("CINS Army bad actors", "https://cinsscore.com/list/ci-badguys.txt", "ip_list"),
]


def upgrade() -> None:
    op.execute("""
        CREATE TABLE ioc_feeds (
            id            serial PRIMARY KEY,
            name          text NOT NULL UNIQUE,
            url           text NOT NULL,
            format        varchar(16) NOT NULL CHECK (format IN ('ip_list', 'hostfile', 'spamhaus_json')),
            enabled       boolean NOT NULL DEFAULT true,
            last_fetched  timestamptz,
            last_count    integer,
            last_error    text
        )
    """)
    op.execute("""
        CREATE TABLE ioc_networks (
            feed_id  integer NOT NULL REFERENCES ioc_feeds(id) ON DELETE CASCADE,
            net      cidr NOT NULL
        )
    """)
    op.execute("CREATE INDEX ix_ioc_networks_net ON ioc_networks USING gist (net inet_ops)")
    op.execute("""
        CREATE TABLE ioc_domains (
            feed_id  integer NOT NULL REFERENCES ioc_feeds(id) ON DELETE CASCADE,
            domain   text NOT NULL
        )
    """)
    op.execute("CREATE INDEX ix_ioc_domains_domain ON ioc_domains (domain)")
    for name, url, fmt in FEEDS:
        op.execute(f"INSERT INTO ioc_feeds (name, url, format) VALUES ('{name}', '{url}', '{fmt}')")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute("""ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN
        ('device_offline', 'vpn_tunnel_down', 'vpn_flapping', 'failed_logins', 'config_change', 'wan_failover',
         'outdated_firmware', 'log_source_silent', 'event_match', 'ioc_match'))""")
    op.execute("INSERT INTO alert_rules (name, rule_type, severity, params) VALUES ('Threat intel match', 'ioc_match', 'high', '{}')")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE rule_type = 'ioc_match'")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute("""ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN
        ('device_offline', 'vpn_tunnel_down', 'vpn_flapping', 'failed_logins', 'config_change', 'wan_failover',
         'outdated_firmware', 'log_source_silent', 'event_match'))""")
    for t in ("ioc_domains", "ioc_networks", "ioc_feeds"):
        op.execute(f"DROP TABLE IF EXISTS {t}")
