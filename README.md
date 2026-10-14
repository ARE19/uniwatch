<p align="center"><img src="docs/uniwatch-banner.jpg" width="600" alt="Uniwatch"></p>

# Uniwatch

**Self-hosted log, alert and report server for UniFi networks, built for MSPs that look after many client sites.**

Uniwatch collects the syslog / CEF events of every client's UniFi gateway, reads live status and configuration through
UniFi Site Manager (or the local controller API), and turns it into dashboards, alerts, CCTV access logs, configuration
history and branded PDF / Excel reports, with each client's data isolated by the database itself.

> Independent open-source project, not affiliated with Ubiquiti. Licensed under the **GNU AGPL-3.0**.

## Screenshots

Taken from a live installation; client names, people, locations and every IP address were replaced before capture.

| | |
|---|---|
| ![Fleet](docs/screenshots/fleet.png) **Fleet**: every site, internet links, devices, alerts | ![Overview](docs/screenshots/overview.png) **Overview dashboard** |
| ![Site overview](docs/screenshots/site-overview.png) **Site overview**: one client at a glance | ![Devices](docs/screenshots/devices.png) **Asset inventory** with firmware and end-of-life |
| ![Websites and apps](docs/screenshots/websites-and-apps.png) **Websites & apps** from traffic flows | ![Devices and usage](docs/screenshots/devices-and-usage.png) **Devices & usage** |
| ![VPN monitor](docs/screenshots/vpn-monitor.png) **VPN monitor**: tunnel availability and drops | ![Log view](docs/screenshots/log-view.png) **Log View** with search and timeline |
| ![Alerts](docs/screenshots/alerts.png) **Alerts** | ![Alert rules](docs/screenshots/alert-rules.png) **Alert rules** per client or company |
| ![CCTV access log](docs/screenshots/cctv-access-log.png) **CCTV access log** (UniFi Protect) | ![Config backups](docs/screenshots/config-backups.png) **Configuration backups** and change history |
| ![Alert e-mail](docs/screenshots/alert-e-mail-triggered.png) **Alert e-mail** when triggered … | ![Resolved e-mail](docs/screenshots/alert-e-mail-resolved.png) … and when resolved |
| ![Report cover](docs/screenshots/report-page-01.png) **PDF report** (executive report pack) | ![Report summary](docs/screenshots/report-page-02.png) Executive summary with KPIs and findings |

A complete sample report: [docs/sample-report.pdf](docs/sample-report.pdf).

## Features

**Visibility**
- Overview, per-site overview, fleet page (every console, problems first) and a rotating NOC wall
- Log View: search with `field=value` filters, saved views, CSV export, live tail, raw lines
- Insights: devices & usage, websites & apps (UniFi traffic flows / IPFIX), top sources and destinations, countries map,
  threats, blocked traffic, DNS filtering, WiFi, admin activity
- VPN monitor: site-to-site tunnel availability and drops, remote-access users and sessions
- CCTV access log from UniFi Protect: who signed in, when, from where, which camera recordings were watched
- Asset inventory: every gateway, switch, AP, camera and door reader with serial, firmware, end-of-life flag;
  firmware-by-model compliance; Excel export

**Alerts** (e-mail, Microsoft Teams, Slack, webhook; resolved notifications; per client, per company or global)
- Internet / WAN down and failover, site-to-site VPN down (with a minimum duration), device offline
- Access point offline, Wi-Fi quality (channel utilisation, Wi-Fi experience, weak client signal), PoE problems
- Failed logins, VPN port scans, threat-intelligence matches (5 free feeds), configuration changes, firmware updates,
  log server self-health
- Branded HTML alert e-mails with times in each site's own time zone; incidents with timeline and comments

**Reports** (PDF + Excel, on demand or scheduled, date range or month, per site or per company)
- Built in: the monthly network report (internet usage, device uptime, VPN tunnel availability, VPN client sessions,
  device sources and destinations), each section also on its own
- More report types come as **report packs** (see below), for example the executive report pack: executive summary
  with KPIs, findings and recommendations, plus traffic & bandwidth, security & attacks, rule & policy, VPN & remote
  access, web & application usage, CCTV access, high availability & system, compliance & audit

**Configuration**
- Configuration backup of every console every 3 hours (16 sections: networks, Wi-Fi, firewall, NAT, routes ...),
  object-level change history with before / after; secrets are never stored
- Local copies of the consoles' own full backup files (.unf), encrypted, admin-only download, 3-month retention

**Multi-tenant by design**
- Clients and companies (several sites of one customer); client users only ever see their own sites
- MFA for everyone, audit log, least-privilege database roles with row-level security

## Quick start

Full step-by-step guide: **[docs/install.md](docs/install.md)** (server preparation, settings, connecting UniFi
sites, alerts, firewall, updates, troubleshooting).


Requirements: a Linux host with Docker Engine + Compose, 4 vCPU / 8 GB RAM / 100 GB+ disk for ~25 sites.

```sh
git clone <this repository> /opt/uniwatch && cd /opt/uniwatch
sh scripts/gen-env.sh                     # writes .env with random secrets (mode 0600)
# edit .env: PUBLIC_URL, SITE_ADDRESSES, SMTP_*, UNIFI_SITE_MANAGER_API_KEY, BRAND_* (optional)
sudo docker compose up -d --build         # db -> migrate -> receiver, parser, poller, reporter, web, caddy
```

Open `https://<server>`, sign in with `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` from `.env` and enrol MFA.
Then: add your clients (Admin → Clients), point each UniFi gateway's SIEM / syslog at the server (UDP 514 or 5141),
and add a UniFi Site Manager API key for fleet status, CCTV, configuration backups and live device data.

Run the test suite (≈1,100 tests against a real PostgreSQL + TimescaleDB):

```sh
sudo docker compose --profile test run --rm tests
```

Operations guide: [docs/runbook.md](docs/runbook.md). Sample data used by the parsers and tests:
[samples/README.md](samples/README.md) (real UniFi output, anonymised).

## Report packs

The core is complete without them. A report pack adds report types and is installed by an admin on
**System Settings → Report packs** by uploading two files: the pack (`.uwpack`) and a licence (`.uwlic`). Both are signed
by the pack publisher; a file that is unsigned, altered, expired or from another publisher is refused, because a pack
contains program code. Packs are not part of this repository and are licensed separately by their publisher.

To publish your own packs, make a signing key with `scripts/make_pack.py keygen`, put its public key in `.env` as
`PACK_PUBLIC_KEY`, and build pack and licence files with the same script. `PACK_PUBLIC_KEY=` (empty) switches packs off.

## Branding

Reports and alert e-mails use neutral Uniwatch branding by default. Put your own company name, address, colours and
logo in `.env` (`BRAND_*` variables, see `.env.example`).

## Stack

Python 3.12, FastAPI, SQLAlchemy 2 + Alembic, psycopg 3, PostgreSQL 16 + TimescaleDB, HTMX + Jinja2, ECharts,
WeasyPrint + openpyxl, Caddy.

## Licence

Copyright (C) 2026 ARE19. Uniwatch is free software under the GNU Affero General Public License v3.0
(see [LICENSE](LICENSE)); third-party components are listed in [NOTICE](NOTICE). If you offer a modified Uniwatch to
users over a network, the AGPL requires you to make your modified source available to them. Report packs are optional,
separate add-ons licensed by their publisher.

Security issues: see [SECURITY.md](SECURITY.md). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
