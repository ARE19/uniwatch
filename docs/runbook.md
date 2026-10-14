# Uniwatch: runbook

Example host: a Linux VM (Ubuntu 24.04 tested) at 192.168.1.50 with Docker Engine and the Compose plugin.
Project root in these examples: **`/opt/uniwatch`** (put it on a dedicated data disk). UI: **https://192.168.1.50**.

## Containers

| Container          | Purpose | Ports |
|--------------------|---------|-------|
| uniwatch-db       | PostgreSQL 16 + TimescaleDB 2.30.2 | `127.0.0.1:5432` (loopback only) |
| uniwatch-migrate  | one-shot: `alembic upgrade head` + first admin | — |
| uniwatch-receiver | syslog listener, **host network** | `514`, `5141` UDP + TCP |
| uniwatch-parser   | parser workers + VPN state tracker + GeoIP refresh | — |
| uniwatch-poller   | UniFi controller API poller + device up/down state | — (outbound to controllers) |
| uniwatch-reporter | APScheduler: reports, monthly schedules, alert rules, threat-intel feeds/matching, forwarding, retention | — |
| uniwatch-web      | FastAPI + HTMX UI (2 workers) | — (Caddy only) |
| uniwatch-caddy    | TLS reverse proxy (internal CA) | `192.168.1.50:443`, `:80` |

## Database roles and tenant isolation

| Role | Used by | Rights |
|------|---------|--------|
| `postgres` | init / maintenance only | superuser |
| `uniwatch_owner` | migrations | owns the schema |
| `uniwatch_app` | receiver, parser, poller, reporter | DML on tables (no raw-log DELETE; retention runs via a definer function) |
| `uniwatch_web` | web UI only | **no access to log hypertables/aggregates** (only the `scoped.*` views that shadow them via `search_path`), **row-level security** on every client table, no access to poller credentials or cursors |

The web role's visible clients are computed in the database from `app.user_id` (set per transaction by the
app): active admins/engineers see all clients, `client_readonly` users only their `user_clients`. RLS cannot
be enabled on compressed TimescaleDB hypertables (2.30: "operation not supported on hypertables that have
columnstore enabled"), which is why those are reached only through views. Proof: `tests/test_tenancy.py`
(unfiltered queries as the web role return only the caller's client).

Existing installs: `sudo sh scripts/upgrade-roles.sh` creates `uniwatch_web` and adds `DB_WEB_PASSWORD` to `.env`.

## Everyday commands (in `/opt/uniwatch`)

```sh
sudo docker compose ps
sudo docker compose logs -f receiver            # also: parser, poller, reporter, web
sudo docker compose build migrate && sudo docker compose up -d     # deploy (build the shared image ONCE)
sudo docker compose --profile test run --rm tests                   # the full test suite against uniwatch_test
```
Build via the `migrate` service only: parallel per-service builds of the same image corrupted the BuildKit
cache once (`sudo docker builder prune -af` fixes it).

## Users

- Admin CLI runs in a container that has the app credentials (not `web`):
  `sudo docker compose run --rm migrate python -m app.cli reset-mfa <user>` / `set-password <user>`.
- MFA is mandatory; 10 failed passwords in 15 min lock a username; 5 wrong codes end the session.
- Roles: admin (everything), engineer (all clients, no user/storage admin), client_readonly
  (Dashboard, Insights, VPN monitor, Reports for their own clients only).

## Ingest

- Receiver listens on **514 and 5141, UDP and TCP** (RFC 6587 framing). Unregistered senders are counted under
  *Log sources → Unknown senders* (lines not stored) until registered.
- Parser (`app/parsers/vendors/unifi.py`) is built only from real lines in `samples/`; every sample line is a test.
  Re-parse after parser changes:
  `sudo docker compose exec parser python -m app.parserd replay --client nwhk --since 2026-10-06T00:00:00+08:00`
- VPN state is derived from events; rebuild: `sudo docker compose exec parser python -m app.parserd vpn-rebuild`.
- GeoIP: DB-IP Lite (free, CC BY 4.0) refreshed monthly into `volumes/geoip`. MaxMind GeoLite2-City/ASN `.mmdb`
  files dropped into that folder take precedence automatically.
- FortiGate devices (vendor `fortinet`) use the generic CEF/syslog parser until real FortiGate samples exist.

## Polling (UniFi)

`cat api.key | sudo docker compose exec -T poller python -m app.poller set-unifi --client nwhk --device NW-HK --url https://192.168.1.1`
(key read from stdin, stored encrypted; the controller certificate is pinned on the first poll).
Test: `sudo docker compose exec poller python -m app.poller poll-once --client nwhk --device NW-HK`.
Verified against UniFi Network 10.6.106 / UniFi OS 5.1.33.

## Alerts, reports, intel, forwarding

- Event Monitor rules run every 60 s (reporter). Notification channels (e-mail/Teams/Slack/webhook) are added by
  an admin; until then alerts show in the UI only.
- **E-mail is disabled until SMTP is set** in `.env` (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`,
  `SMTP_FROM`), then `sudo docker compose up -d`.
- Reports: PDF + Excel in `volumes/reports/<client>/`; monthly schedules on the Reports page.
- Report packs: files in `volumes/packs/` (`<id>.uwpack` + `<id>.uwlic`, owner uid 10001), uploaded on System Settings →
  Report packs; checked against `PACK_PUBLIC_KEY` and loaded by the web and reporter containers without a restart. A
  report of a pack that is missing or whose licence has expired fails with "needs a report pack"; runs already generated
  stay downloadable. Make files with `scripts/make_pack.py` (publisher only).
- Executive summary report (`firewall_bundle`, from the executive report pack): executive summary + traffic & bandwidth, security & attacks, rule & policy,
  VPN & remote access, web & applications, HA & system; each (and compliance & audit) also available on its own. Charts are
  SVG in the PDF; every table and chart's data is a sheet in the Excel file. Traffic shares come from the
  `events_traffic_1h` aggregate (auto-refresh covers 3 days: after importing history run
  `CALL refresh_continuous_aggregate('events_traffic_1h', '<from>', now() - interval '1 hour')` as the owner).
- Rule & policy data: the poller snapshots each gateway's firewall policies and zones hourly (`firewall_policies`,
  `firewall_zones`), from the local API or through the Site Manager connector. Hit counters are UniFi's own.
- Compliance checks are indicative evidence against PCI DSS v4.0 / NIST SP 800-53 controls, not a certification.
- Threat intel: 5 free feeds (Feodo, URLhaus, Spamhaus DROP, ET compromised, CINS) refreshed every 6 h.
- Forwarding: System → Storage & forwarding (raw/CEF/JSON over UDP/TCP/TLS; starts at "now").
- Retention: per-client `retention_days`, enforced every 6 h by `apply_retention()`; compression after 7 days.

## Websites & apps (UniFi traffic flows)

- The poller collects the firewall's own connection records from the controller API (`POST .../v2/api/site/<site>/traffic-flows`)
  for every UniFi device with `poll_config.collect_flows = true`. Turn it on or off per firewall:
  `sudo docker compose exec poller python -m app.poller set-flows --client <slug> --device "<name>" on|off`.
  Note that `set-unifi` rewrites the poll config, so run `set-flows ... on` again after it.
- Records are stored one JSON object per raw line (`raw_logs.transport = 'api'`) and parsed by `app/parsers/vendors/unifi_flow.py`.
  Collection lags 3 minutes (open flows can still change) in contiguous windows. After an outage it catches up 30 minutes per cycle,
  back to at most 6 hours.
- Events: `action = flow` (allowed) or `flow-blocked`, with src/dst IP, ports, MACs, bytes_in = download and bytes_out = upload of
  the source device. Log View can search them, e.g. action `flow` plus an IP for one device's sessions.
- Views: Insights → Websites & apps (data volume per app, category, website, device), the IP page, and the dashboard widgets
  Top apps, Top websites and Top devices by data. They read the `events_web_1h` aggregate (outgoing flows plus DNS lookups).
- Volume at NW-HK: about 300 records a minute, about 1.1 KB each before compression. Per-client retention applies.
- Devices running the Microsoft Global Secure Access client tunnel their traffic, so only the tunnel is visible
  ("Microsoft Global Secure Access (tunnel)").
- Remote firewalls the server cannot reach over the API: see NetFlow below.

## NetFlow / IPFIX

- The receiver decodes IPFIX (NetFlow v10) on UDP 2055 (`app/receiver/ipfix.py`, from real UniFi exports in
  `samples/netflow-ipfix-*.hex`). Each flow record (one direction of a connection) becomes a raw line (JSON, transport
  `netflow`) of the sending device and an event `action = netflow` (Log View → Traffic, Insights sources/destinations).
  Templates are read by field, never by template id (ids differ per UDM); interface numbers become names (eth7, br0).
- Devices whose flows come from the controller API (`collect_flows`, e.g. NW-HK) are skipped to avoid double counting.
- The first 300 datagrams per sender are still kept in `volumes/netflow-capture/<ip>.hex` as samples.
- CTS SG / CTS KL (2026-10-07) export only option records (interfaces, statistics), no flow records: on their UDM, select
  the LAN network(s) in the NetFlow setting and set Sampling Off.

## DNS forwarder (optional)

- Off by default (compose profile `dns`); the traffic-flow API replaces it. Start with `sudo docker compose --profile dns up -d dns`
  and reactivate the "DNS forwarder" device.
- `dns` container: CoreDNS 1.14.7 on 192.168.1.50:53 (host network, `dns/Corefile`). It answers private ranges only, forwards to
  the UDM (`DNS_UPSTREAM`, default 192.168.1.1) and caches for 30 s. It logs each query through Docker's syslog driver (RFC 5424, UTC)
  to the receiver on 127.0.0.1:5141, where the device "DNS forwarder" (vendor `dns`) picks them up.
- Parser: `app/parsers/vendors/dns.py`. Mapping from domain to site/app/category, shared with the flow parser: `app/intel/apps.py`
  (`CATALOGUE`). To add an app, add its domain suffixes, redeploy and replay (`parserd replay --client <slug> --since ... --device ...`).
- To use it, set the UDM DHCP DNS to 192.168.1.50 (primary) and the UDM (secondary). Limits: no data volume; DNS-over-HTTPS bypasses it.

## Log View search

- Tabs: All, Traffic (traffic + firewall), Security (IDS + DNS filtering), VPN, System event. Toolbar: device, time range,
  Custom views (saved: tab, range, device, search, columns), Refresh, Columns, More (CSV, live tail, raw lines).
- Search box: `field=value` filters plus free text, e.g. `srcip=192.168.1.0/24 dstport=80,443 app="Microsoft Teams"`,
  `remote=*.microsoft.com`, `action!=flow`, `rcvd>1000000`. ⊕ lists every field (`app/web/logquery.py` FIELDS).
  Right-click a value in the table to filter by or exclude it.

## Event Monitor rules

- Rules tab: one row per rule (on/off, client, severity, e-mail recipients). Click a row to edit: Enabled switch, Client
  (all clients or one), Severity, the rule's thresholds, and "Send e-mail to" (comma-separated). Those addresses are stored
  encrypted as a channel owned by the rule (`notification_channels.owner_rule_id`, migration 0019) and are not listed under
  Notification channels. Shared channels (Teams, NOC e-mail) are under "More options".
- Different recipients per client: "Copy for another client" creates a disabled copy named "<rule> (<client>)" next to the
  original; set its addresses and switch it on. Client copies can be deleted; built-in rules for all clients can only be switched off.
- "Send test e-mail" sends to the rule's saved addresses.

## Importing a device's own log files

- Copy the files to `import/<client>/<date>/` (owner uid 10001 = the container user, group admin, read-only), then:
  `sudo docker compose exec parser sh -c "cd /srv/import/<client>/<date> && python -m app.parserd import-files --client <slug>
  --device <name> [--skip REGEX] FILES..."`. Lines keep their own timestamps (transport `import`), duplicates across files are
  stored once, completed files are skipped on a re-run. The command waits for parsing and then refreshes the Insights
  summaries over the imported span (they only re-scan the last 3 days on their own).
- Then rebuild that client's VPN history in time order: `python -m app.parserd vpn-rebuild --client <slug>`
  (never the plain `vpn-rebuild`: it also wipes tunnel aliases and the poller's IPsec state).
- Threat-intel alerts fire only for hits newer than the rule's "Only hits newer than (hours)" (default 24), so imported
  history shows in Insights/Log View without raising alerts.

## Navigation and investigation

- Top-bar search (staff, press `/`): IP → its page, CIDR → Log View, MAC → that device, otherwise device names, hostnames,
  VPN users and websites. `/ip/<ip>` is the device 360 (identity from the controller, security counts, VPN sessions, DHCP/WiFi,
  websites & apps, peers, events); `/vpn/user?name=…` is the VPN user 360.
- Dashboard: click a time chart → Log View for that interval; category bars, app/website/threat rows → their events.
- Log View: timeline above the results (click a bar to zoom in), "Group by" any field with counts, data and drill-down.
- Insights → Countries & map: world map of attack sources or traffic destinations (`app/static/world.geo.json`,
  Natural Earth 1:110m, public domain); click a country for its events.
- Alerts: `/event-monitor/alerts/<id>` with comments, acknowledge/resolve, related events. Alert e-mails and Teams messages
  link there when `PUBLIC_URL` is set in `.env` (e.g. https://192.168.1.50).
- NOC wall: `/wall` rotates through clients full screen (15/30/60 s, ← → to switch, space to pause).
- Per-device "normal silence" (Log sources → edit): how long a quiet device may go without logs before "silent"/"offline".

## Dashboards

- Customise (top right of the dashboard): drag or ◀ ▶ to reorder, ⅓ / ½ / Full width, ✕ to remove, + Add widget. Save as your
  own dashboard, or (staff) share it with everyone or with one client's users, optionally as their default.
- Which dashboard a user sees: their own choice, else the default shared with their client, else the global default, else the
  standard layout (`app/web/widgets.py` `DEFAULT_LAYOUT`). Row-level security on `dashboards` allows client users only private
  dashboards; staff manage shared ones.
- Staff can add a "Saved search" widget: the count and trend of any saved Log View search (e.g. `action = flow-blocked`).

## Backups

- Service `backup` (`db/backup.sh`): full `pg_dump -Fc` every day at 18:30 UTC (02:30 HKT) into `BACKUP_DIR` (see below), keeping
  14 days (`BACKUP_AT_UTC`, `BACKUP_KEEP_DAYS`). Each run is recorded in the audit log (`db_backup`, success true/false).
  On demand: `sudo docker compose exec backup sh /backup.sh now`.
- Restore (into a scratch database first, then switch over):
  ```sh
  sudo docker compose exec -T db psql -U postgres -c "CREATE DATABASE uniwatch_restore"
  sudo docker compose exec -T db psql -U postgres -d uniwatch_restore -c "CREATE EXTENSION timescaledb" -c "SELECT timescaledb_pre_restore()"
  sudo cat /backup/uniwatch/<file>.dump | sudo docker compose exec -T db pg_restore -U postgres -d uniwatch_restore
  sudo docker compose exec -T db psql -U postgres -d uniwatch_restore -c "SELECT timescaledb_post_restore()"
  ```
- Location: `BACKUP_DIR` in `.env`, e.g. `/backup/uniwatch` on a separate disk (ideally another physical volume than the
  database). It is still the same host: copy the dumps off the box (NAS / cloud) for real disaster recovery.

## Recommended host settings

- cgroup v2 and the nftables iptables backend (Docker's defaults on current distributions).
- `/etc/docker/daemon.json`: container log rotation, e.g. `{"log-driver": "json-file", "log-opts": {"max-size": "50m", "max-file": "3"}}`.
- `/etc/sysctl.d/90-log-receiver.conf`: `net.core.rmem_max=33554432` and `net.core.netdev_max_backlog=5000` for UDP syslog bursts.
- Use NTP on the host (disable the hypervisor's own time sync for the VM if it fights NTP).
- Host firewall (e.g. ufw): SSH/HTTPS from your management networks only, 514/5141 (syslog) and 2055 (IPFIX) only from your
  devices; Docker-published ports also need rules in the `DOCKER-USER` chain.
