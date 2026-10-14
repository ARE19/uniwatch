# Installing Uniwatch

This guide takes a fresh Linux server to a working Uniwatch that receives logs from your UniFi gateways. About 30–60
minutes. Commands are for Ubuntu 24.04; any Linux with Docker works.

## 1. Requirements

| | Minimum (≈25 sites) | Notes |
|---|---|---|
| CPU / RAM | 4 vCPU / 8 GB | 8 vCPU / 16 GB+ for 50+ sites or many traffic flows |
| Disk | 100 GB | 3 months of logs for 25 sites ≈ 50–150 GB; use a separate data disk if you can |
| Backup disk | optional | a second disk (or NAS mount) for the nightly database dump and firewall backups |
| OS | Linux x86-64 with Docker Engine 24+ and the Compose plugin | tested on Ubuntu 24.04 |
| Network | a fixed IP; inbound UDP/TCP 5141 (and/or 514) from your gateways; HTTPS for users | outbound HTTPS to api.ui.com for UniFi Site Manager |

## 2. Prepare the server

```sh
# Docker Engine + Compose plugin (official convenience script; or follow docs.docker.com/engine/install)
curl -fsSL https://get.docker.com | sudo sh

# Larger UDP buffers for syslog bursts
printf 'net.core.rmem_max=33554432\nnet.core.netdev_max_backlog=5000\n' | sudo tee /etc/sysctl.d/90-uniwatch.conf
sudo sysctl --system

# Docker log rotation (container logs only; your firewall logs live in the database)
echo '{"log-driver":"json-file","log-opts":{"max-size":"50m","max-file":"3"}}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

Make sure the clock is right (NTP): `timedatectl` should say `System clock synchronized: yes`.

## 3. Get Uniwatch and create the settings file

```sh
sudo mkdir -p /opt/uniwatch && sudo chown $USER /opt/uniwatch
# copy or clone the Uniwatch files into /opt/uniwatch, then:
cd /opt/uniwatch
sh scripts/gen-env.sh          # creates .env with a random value for every password and key (mode 0600)
```

Open `.env` and set at least these (the comments in the file explain every setting):

| Setting | Set it to |
|---|---|
| `CADDY_BIND` | the server's IP, e.g. `192.168.1.50` (default `127.0.0.1` = reachable from the server itself only) |
| `SITE_ADDRESSES` | the addresses people type in the browser, e.g. `https://192.168.1.50, https://uniwatch.example.com` |
| `DEFAULT_SNI` | the address people browse to, e.g. `192.168.1.50` |
| `PUBLIC_URL` | the same address, e.g. `https://192.168.1.50` (used for links in alert e-mails) |
| `INITIAL_ADMIN_USERNAME` | your first admin's user name (the password was generated: note `INITIAL_ADMIN_PASSWORD`) |
| `DEFAULT_TIMEZONE` | your main time zone, e.g. `Asia/Hong_Kong` or `Europe/London` |
| `BACKUP_DIR` | optional: a folder on another disk for the nightly database dump, e.g. `/backup/uniwatch` |
| `UNIFI_SITE_MANAGER_API_KEY` | optional now, see step 6 |
| `BRAND_*` | optional: your company name, address, colours and logo on reports and e-mails |

`DB_TUNE_MEMORY` / `DB_TUNE_CPUS`: set them to what the database may use (e.g. half the server's RAM).
**Keep `.env` private and back it up**: it holds every password and the key that encrypts the stored secrets; without it
the stored API keys and firewall backups cannot be decrypted.

## 4. Start

```sh
sudo docker compose up -d --build
sudo docker compose ps          # after 1–2 minutes: db healthy, migrate exited (0), the others running
```

The first start builds the image, creates the database, its roles and tables, and the first admin.

Optional, recommended once: run the test suite (about 1,100 tests, 10–60 minutes depending on the machine):

```sh
sudo docker compose --profile test run --rm tests
```

## 5. First sign-in

1. Browse to `https://<server address>`. The certificate comes from Caddy's own internal CA, so the browser warns the first
   time: accept it (or put a reverse proxy with a real certificate in front, or give Caddy a public domain).
2. Sign in with `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` from `.env`.
3. Change the password and enrol MFA (any authenticator app: Microsoft / Google Authenticator, 1Password …).
4. **System Settings → Users**: add the other admins / engineers (and read-only client users, each limited to their clients).
5. **System Settings → Mail (SMTP)**: your mail server (e.g. `smtp.office365.com:587` + mailbox, or Microsoft 365 direct send
   `<tenant>.mail.protection.outlook.com:25` without a password), then **Send test e-mail**.

## 6. Connect your UniFi sites

### How Uniwatch gets its data: two channels, both recommended

| | **API: UniFi Site Manager key** (6a) | **SIEM / syslog from each gateway** (6b) |
|---|---|---|
| Direction | Uniwatch **asks** UniFi's cloud (outbound HTTPS to api.ui.com) | each gateway **sends** its logs to Uniwatch (inbound UDP 5141) |
| Set up | once, one key for all consoles of the account | once per gateway |
| What it gives | the **state** of everything: which sites, devices and WAN links are up, inventory and firmware, CPU / memory / clients, VPN tunnel state, configuration backups, CCTV access log | the **events**: every allowed and blocked connection, IDS / IPS and threat detections, VPN sign-ins and failures, admin sign-ins and changes, DHCP and Wi-Fi events, with exact times |
| Without it | no fleet view, no device-offline / internet-down / firmware alerts, no inventory, config backups or CCTV log | no log search, no security / failed-login / scan alerts, no traffic, websites and VPN-user reports |

In short, the **API answers "how is it now?"** and the **SIEM feed answers "what happened, and who did it?"**. Site
Manager only reports current state and a few metrics; it does not hand over the gateway's logs. The gateway's logs, in
turn, say nothing about devices that are silent or offline. The executive reports use both.

### Ports

| Port | Direction | Needed for |
|---|---|---|
| **UDP 5141** (or 514) | gateways → Uniwatch, **inbound** | the SIEM / syslog feed (6b). For remote sites: a port-forward on the Uniwatch site's router plus a firewall rule allowing only your gateways' WAN IPs |
| TCP 443 | outbound to api.ui.com | the Site Manager API (6a); nothing to open inbound |
| TCP 443 (and 80) | your staff → Uniwatch, inbound | the web portal; keep it to your management network or a VPN |
| UDP 2055 | gateways → Uniwatch, inbound | only if you use NetFlow (6c) |
| TCP 443 | Uniwatch → each console | only for the optional local API (6c) |

### a) UniFi Site Manager (recommended: covers every console with one key)

1. At **unifi.ui.com → API**, create a Site Manager API key (owner of the consoles).
2. In the portal open **System Settings → UniFi Site Manager**, paste the key, **Save**, then **Test connection**.
   (No server access needed. A key in `.env` as `UNIFI_SITE_MANAGER_API_KEY` also works; one saved in the portal wins.)
3. Within 5 minutes Uniwatch lists every console under **Dashboards → Fleet** and **creates one client per console**
   (named after the console, with its time zone and WAN IPs). Rename clients or group them into companies under
   **System Settings → Clients**.

This alone gives: internet / WAN status and latency, device inventory and firmware, live CPU / memory / clients,
site-to-site VPN status, CCTV access log (UniFi Protect), configuration backups and history, and most alerts.

### b) Syslog / SIEM from each gateway (logs, security events, VPN users, admin activity)

On each gateway, in UniFi Network: **Settings → Control Plane → Integrations → Activity Logging (SIEM Server)**
(the menu name varies with the UniFi Network version; look for "SIEM", "Syslog" or "Activity Logging"):

- Server: the Uniwatch server's address as the gateway sees it (its LAN IP on the same network, or your **public IP**
  for remote sites, with a port-forward of UDP 5141 to the server and, ideally, a firewall rule that only allows your
  gateways' WAN IPs).
- Port: **5141** (UDP). Port 514 also works.
- Enable the categories you want (all is fine).

Uniwatch accepts logs only from known sources. Gateways found through Site Manager are known by their WAN IPs, so their
logs are filed under the right client automatically. Anything else shows under **Device Manager → Log sources → Unknown
senders**: register it there (or with **Device Manager → Add device**: client, name, source IP).

### c) Optional extras per site

- **Local API (richer data: per-device bandwidth, traffic flows, full backup files)** for a console reachable from the
  server: create an API key on the console (UniFi Network → Settings → Control Plane → Integrations → Create API Key), then
  ```sh
  cat api.key | sudo docker compose exec -T poller python -m app.poller set-unifi --client <client-slug> --device "<device name>" --url https://<console-ip>
  sudo docker compose exec poller python -m app.poller set-flows --client <client-slug> --device "<device name>" on
  ```
- **NetFlow / IPFIX** (traffic per device where the API is not available): on the gateway enable NetFlow to the server, UDP
  port 2055, with your LAN network(s) selected.
- **UniFi auto-backup**: set each console to make a weekly backup (Settings → System → Backups); Uniwatch copies them for
  consoles it reaches locally.

## 7. Alerts and reports

- **Incidents & Events → Notification channels → + Create new**: an e-mail address, Microsoft Teams / Slack webhook or
  generic webhook. A channel can be for all clients (your NOC), one client or one company.
- **Incidents & Events → Event handlers**: switch rules on/off, set thresholds, attach channels; "Copy for another client"
  makes a client- or company-specific version with its own recipients.
- **Reports**: generate on demand (date range or a preset) or schedule monthly e-mails per client.
- **Report packs** (optional, extra report types): `sudo mkdir -p volumes/packs && sudo chown 10001 volumes/packs` once,
  then **System Settings → Report packs** and upload the pack file and the licence file you received.
- Make a client for your own company and put its slug in `.env` as `PLATFORM_CLIENT_SLUG` so the server's self-health
  alerts (no logs, disk full, failed backups) have somewhere to go; add your e-mail to the "Log server health" rule.

## 8. Firewall on the Uniwatch server

Allow only what is needed, e.g. with ufw:

```sh
sudo ufw allow from <your management network> to any port 22,443 proto tcp
sudo ufw allow from <gateway IP or public range> to any port 5141 proto udp   # one line per source (or a range)
sudo ufw allow from <gateway IP> to any port 2055 proto udp                  # only if you use NetFlow
sudo ufw enable
```

The receiver uses the host network, so these rules apply to it directly. Ports Docker publishes (Caddy 80/443) bypass ufw
unless you add rules to the `DOCKER-USER` iptables chain; binding Caddy to one IP (`CADDY_BIND`) already limits them to
that interface.

## 9. Updating

```sh
cd /opt/uniwatch
# replace the files with the new version (git pull, or copy) - keep .env and volumes/
sudo docker compose --profile test run --rm tests      # recommended: the new version against a test database
sudo docker compose up -d --build                      # database migrations run automatically (migrate service)
```

## 10. Backups and restore

- The `backup` service writes a full database dump every night into `BACKUP_DIR` (14 days kept). Copy `BACKUP_DIR` and
  `.env` off the server (NAS / cloud) for disaster recovery.
- Restore: see [runbook.md](runbook.md#backups).

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| Browser cannot reach the UI | `CADDY_BIND` is the server IP (not 127.0.0.1); `sudo docker compose ps caddy web`; port 443 open |
| Certificate error that does not go away | `SITE_ADDRESSES` / `DEFAULT_SNI` contain exactly the address you browse to |
| A gateway's logs do not arrive | Log sources → Unknown senders (register it); `sudo docker compose logs --tail 50 receiver`; port-forward / firewall for UDP 5141 |
| Logs arrive but nothing is parsed | `sudo docker compose logs --tail 50 parser` |
| Fleet page empty | `UNIFI_SITE_MANAGER_API_KEY` set and `docker compose up -d` run; `sudo docker compose logs --tail 50 poller` |
| No e-mails | System Settings → Mail (SMTP) → Send test e-mail shows the mail server's answer |
| Locked out / lost MFA device | `sudo docker compose run --rm migrate python -m app.cli reset-mfa <user>` or `set-password <user>` |

More operational detail: [runbook.md](runbook.md).
