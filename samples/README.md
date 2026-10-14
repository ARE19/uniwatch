# Samples

Real lines from UniFi deployments, **anonymised** for publication: client, site, device and people names are replaced by
fictional ones (Northwind, Contoso, Tailspin ...), client-owned public IPs moved to 11.0.0.0/8, device MACs and serials
re-generated (vendor prefix kept), console ids replaced. Internet addresses of scanners and public services are kept.
The structure, field names, ordering and byte layout are exactly as received: the parsers are built and tested on them.

Source: NW-HK UDM Pro SE (UniFi Network 10.6.106) and its APs/switch, 192.168.1.50:5141/udp.
Lines are exactly as received (RFC3164 header, local time UTC+8, no zone).

- udm-cef.log: up to 5 lines per CEF event class seen (400, 401, 402, 544, 200)
- udm-syslog-by-process.log: up to 25 non-CEF lines per process, each preceded by `# <process>`

These are a starting point. They are NOT the full sample set the brief asks for (no VPN connect/
disconnect, no admin config change in CEF were seen in this window).
- udm-live-2026-10-06.log: lines received by the new receiver on 2026-10-06 16:25-16:35 HKT (incl. CEF 546 Config Modified,
  CoreDNS ad-block JSON, OpenVPN client tunnel tunovpnc1 up/down, blebrd, syslog-ng).

Every non-comment line in these files is a parser test case (tests/test_parsers_unifi.py): it must parse without error.
- coredns-forwarder-2026-10-07.log: the project's own CoreDNS forwarder (dns/Corefile) as delivered by Docker's syslog driver
  (rfc5424micro, tag coredns): startup lines and query lines "[INFO] client port proto qtype name. rcode size duration".
- unifi-api-traffic-flows-2026-10-07.log: real records from the NW-HK controller API
  `POST /proxy/network/v2/api/site/default/traffic-flows` (Network 10.6.106), one JSON object per line, exactly as
  returned: HTTPS with domains, no domain, blocked (ad blocking), incoming, local, open (no end time), no traffic_data,
  DNS, count>1 and the largest flows. Byte direction verified on a Windows Update HTTP download (Fastly):
  traffic_data.bytes_tx = bytes to the initiating device (download), bytes_rx = bytes from it (upload).
- udm-cts-sg-2026-10-07.log: CTS SG UDM (UniFi Network 10.6.106) over the internet (port forward, WAN1 11.145.54.44),
  received 2026-10-07: CEF 521 VPN Client Disconnected for a WireGuard remote-access user and CEF 520 VPN Client Connected
  (first real remote-access VPN samples).
- udm-cts-kl-files-2026-10-07.log / udm-cts-kl-files-history.txt: lines from CTS KL's own log FILES (/var/log/messages,
  daemon.log, auth.log, ulog/threat.log; copied 2026-10-07 over SSH), syslog-ng file format
  `2026-10-06T17:38:33+08:00 CTS-KL prog[pid]: msg`: WireGuard server peers, EVT_VPN for those peers, strongSwan charon
  (IKE established / initiating / reauth / CHILD_SA closed / NO_PROP), dnsmasq-dhcp, sudo. The .txt file holds older
  lines (DPD timeout, inbound IKE, IDS alert JSON) outside the one-day window of the every-line test.
- netflow-ipfix-*.hex: real IPFIX (NetFlow v10) datagrams received on UDP 2055, one per line as "<received-at> <hex>":
  NW-HK UDM (templates, interface-name and exporter-statistics option records, flow records; sampling 1:512 was still on)
  and CTS KL (option records only: its export had no flow records at the time).
