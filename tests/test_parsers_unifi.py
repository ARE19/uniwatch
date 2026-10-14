"""UniFi module, tested only against real lines from samples/."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.parsers.vendors import module_for

NOW = datetime(2026, 10, 6, 9, 0, tzinfo=UTC)
TZ = "Asia/Hong_Kong"
SAMPLES = Path(__file__).resolve().parent.parent / "samples"
unifi = module_for("unifi")


def _sample_lines():
    for f in sorted(SAMPLES.glob("*.log")):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip() and not line.startswith("# "):
                yield pytest.param(line, id=f"{f.stem}:{n}")


def find(fragment: str) -> str:
    for f in sorted(SAMPLES.glob("*.log")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if fragment in line and not line.startswith("# "):
                return line
    raise AssertionError(f"no sample containing {fragment!r}")


@pytest.mark.parametrize("line", list(_sample_lines()))
def test_every_real_sample_line_parses(line):
    ev = unifi.parse(line, TZ, NOW)
    assert ev.vendor == "unifi" and ev.ts.tzinfo is not None
    assert abs((ev.ts - NOW).total_seconds()) < 86400  # all samples are from 2026-10-06


def test_cef_threat_detected():
    ev = unifi.parse(find("|200|Threat Detected|7|UNIFIcategory=Security UNIFIhost=NW HK proto=TCP spt=51297"), TZ, NOW)
    assert (ev.category, ev.action, ev.outcome, ev.severity) == ("ids", "ids-detect", "allowed", "high")
    assert (ev.src_ip, ev.dst_ip, ev.dst_port, ev.protocol) == ("10.172.16.125", "192.168.1.50", 22, "tcp")
    assert ev.rule == "ET SCAN Potential SSH Scan" and ev.extra["signature_id"] == "2001219"
    assert ev.interface == "MSP-ISONET" and ev.bytes_out == 66
    assert ev.ts == datetime(2026, 10, 6, 5, 18, 25, 50000, tzinfo=UTC)  # UNIFIutcTime


def test_cef_wifi_connect():
    ev = unifi.parse(find("|400|WiFi Client Connected|1|UNIFIcategory=Client Devices UNIFIhost=NW HK UNIFIconnectedToDeviceName=NWHKWAP-02 UNIFIconnectedToDeviceIp=192.168.1.150 UNIFIconnectedToDeviceMac=70:a7:41:b6:cd:eb UNIFIconnectedToDeviceModel=U6-Lite UNIFIconnectedToDeviceVersion=6.7.57 UNIFIclientAlias=Watch"), TZ, NOW)
    assert (ev.category, ev.action, ev.src_ip, ev.src_mac) == ("wifi", "wifi-connect", "192.168.1.192", "2e:c8:19:6a:82:cc")
    assert ev.extra["ssid"] == "Example MSP Wifi" and ev.extra["ap"] == "NWHKWAP-02" and ev.extra["rssi"] == "-78"
    assert ev.severity == "low"


def test_cef_wifi_roam():
    ev = unifi.parse(find("|402|WiFi Client Roamed|"), TZ, NOW)
    assert ev.action == "wifi-roam" and ev.extra["previous_ap"] and ev.extra["ap"]


def test_cef_admin_access():
    ev = unifi.parse(find("|544|Network Accessed|4|UNIFIcategory=Audit UNIFIhost=NW HK UNIFIaccessMethod=web UNIFIadmin=Unifi Owner src=11.26.85.18"), TZ, NOW)
    assert (ev.category, ev.action, ev.user_name, ev.src_ip) == ("auth", "admin-access", "Unifi Owner", "11.26.85.18")
    assert ev.extra["access_method"] == "web" and ev.severity == "medium"


def test_cef_config_modified_produces_config_change():
    ev = unifi.parse(find("|546|Config Modified|"), TZ, NOW)
    assert (ev.category, ev.action, ev.user_name) == ("config", "config-change", "Unifi Owner")
    assert ev.rule == "System / rsyslogd"
    c = ev.config_change
    assert c["admin_user"] == "Unifi Owner" and c["source_ip"] == "11.26.85.18"
    assert c["summary"] == "System / rsyslogd: port: 514"


def test_ap_prefix_and_duplicate_udm_hostname():
    ap = unifi.parse(find("NWHKWAP-02 70a741b6cdeb,U6-Lite-6.7.57+15670: : mca-monitor[9465]"), TZ, NOW)
    assert ap.process == "mca-monitor" and ap.extra["device_model"] == "U6-Lite"
    assert ap.extra["device_firmware"] == "6.7.57+15670" and ap.extra["device_mac"] == "70:a7:41:b6:cd:eb"
    mcad = unifi.parse(find("mcad: mcad[20980]: ace_reporter"), TZ, NOW)
    assert mcad.process == "mcad"
    lr = unifi.parse(find("78455894e69f,U6-LR-6.7.57+15670: kernel:"), TZ, NOW)
    assert lr.process == "kernel" and lr.extra["device_model"] == "U6-LR"
    udm = unifi.parse(find("NW-HK NW-HK dnsmasq[2022865]: using nameserver"), TZ, NOW)
    assert udm.process == "dnsmasq" and udm.host == "NW-HK" and udm.message == "using nameserver 1.1.1.1#53"


def test_hostapd_wevent_stahtd():
    a = unifi.parse(find("STA 7a:c2:97:62:ed:41 IEEE 802.11: associated"), TZ, NOW)
    assert (a.category, a.action, a.src_mac, a.interface) == ("wifi", "wifi-associate", "7a:c2:97:62:ed:41", "rai0")
    j = unifi.parse(find("EVENT_STA_IP ra0: 00:0a:f5:14:c3:8d / 192.168.1.153"), TZ, NOW)
    assert (j.action, j.src_ip) == ("sta-ip", "192.168.1.153")
    s = unifi.parse(find('"event_type":"soft failure"'), TZ, NOW)
    assert (s.action, s.outcome, s.category) == ("sta-soft-failure", "failure", "wifi")
    leave = unifi.parse(find('"event_type":"sta_leave","assoc_status":"0","event_id":"2","avg_rssi":"-72"'), TZ, NOW)
    assert leave.action == "sta-leave"


def test_dhcp():
    ev = unifi.parse(find("DHCPACK(br0) 192.168.1.60 80:5e:c0:f1:35:d5 SIP-T55A"), TZ, NOW)
    assert (ev.category, ev.action, ev.src_ip, ev.src_mac, ev.interface) == (
        "dhcp", "dhcp-ack", "192.168.1.60", "80:5e:c0:f1:35:d5", "br0")
    assert ev.extra["hostname"] == "SIP-T55A"
    d = unifi.parse(find("DHCPDISCOVER(br0) 00:0a:f5:14:c3:8d"), TZ, NOW)
    assert d.action == "dhcp-discover" and d.src_ip is None


def test_coredns_adblock():
    ev = unifi.parse(find('"domain":"sessions.bugsnag.com"'), TZ, NOW)
    assert (ev.category, ev.action, ev.outcome, ev.rule) == ("dns", "dns-block", "blocked", "ADVERTISEMENT")
    assert ev.src_ip == "192.168.1.27" and ev.extra["domain"] == "sessions.bugsnag.com"


def test_openvpn_server_failed_handshake():
    err = unifi.parse(find("TLS Error: cannot locate HMAC in incoming packet"), TZ, NOW)
    assert (err.category, err.action, err.outcome, err.src_ip, err.src_port) == (
        "vpn", "vpn-tls-error", "failure", "198.235.24.220", 65120)
    tcp = unifi.parse(find("openvpn[3586]: TCP connection established with [AF_INET]85.217.149.17:53516"), TZ, NOW)
    assert (tcp.action, tcp.src_ip) == ("vpn-tcp-connect", "85.217.149.17")
    sig = unifi.parse(find("SIGUSR1[soft,connection-reset]"), TZ, NOW)
    assert sig.action == "vpn-client-restart" and sig.extra["reason"] == "connection-reset"


def test_openvpn_client_tunnel_state():
    up = unifi.parse(find("tunovpnc1: Link UP"), TZ, NOW)
    down = unifi.parse(find("tunovpnc1: Link DOWN"), TZ, NOW)
    assert (up.category, up.action, up.interface) == ("vpn", "link-up", "tunovpnc1")
    assert down.action == "link-down"
    evt = unifi.parse(find("EVT_VPN_ClientConnecting"), TZ, NOW)
    assert (evt.category, evt.action) == ("vpn", "vpn-client-connecting")
    out = unifi.parse(find("ubios-udapi-server[1677793]: 2026-10-06 16:25:12 TCP connection established"), TZ, NOW)
    assert (out.action, out.dst_ip, out.dst_port) == ("vpn-tcp-connect", "11.124.200.216", 1194)


def test_sudo():
    ev = unifi.parse(find("sudo[1692208]: ucs-update : PWD="), TZ, NOW)
    assert (ev.category, ev.action, ev.user_name, ev.extra["run_as"]) == ("auth", "sudo", "ucs-update", "root")


def test_unknown_process_is_kept_as_system_event():
    ev = unifi.parse(find("earlyoom[1786]: mem avail"), TZ, NOW)
    assert (ev.category, ev.action, ev.process) == ("system", None, "earlyoom")
    assert ev.severity == "low" and ev.severity_raw == "info"


def test_evt_vpn_tunnel_fields():
    up = unifi.parse(find("EVT_VPN_ClientConnected server 11.124.200.216:1194 (via tunovpnc1 192.168.200.1/24) on /vpn/openvpn/raws/1"), TZ, NOW)
    assert (up.action, up.interface, up.dst_ip, up.dst_port, up.outcome) == (
        "vpn-client-connected", "tunovpnc1", "11.124.200.216", 1194, "success")
    assert up.extra["vpn_path"] == "/vpn/openvpn/raws/1" and up.extra["tunnel_addr"] == "192.168.200.1/24"
    failed = unifi.parse(find("EVT_VPN_ClientFailed server on /vpn/openvpn/raws/1"), TZ, NOW)
    assert (failed.action, failed.interface, failed.dst_ip, failed.outcome) == ("vpn-client-failed", None, None, "failure")
    assert failed.extra["vpn_path"] == "/vpn/openvpn/raws/1"


def test_cef_521_vpn_user_disconnect_real_sample():
    ev = unifi.parse(find("VPN Client Disconnected"), "Asia/Singapore", NOW)
    assert (ev.category, ev.action, ev.outcome, ev.user_name) == ("vpn", "vpn-user-disconnect", "success",
                                                                  "Kevin Henry Tan's Desktop")
    assert ev.ts.isoformat() == "2026-10-07T03:11:59.344000+00:00"
    assert ev.interface == "CTSSG" and ev.extra["vpn_type"] == "WIREGUARD_SERVER" and ev.extra["duration_s"] == 127
    assert ev.bytes_in == int(51.54 * 1024) and ev.bytes_out == int(21.91 * 1024)
    assert ev.extra["vpn_subnet"] == "192.168.11.0/24" and ev.extra["vpn_server_address"] == "11.145.54.44"


def test_cef_520_vpn_user_connect_real_sample():
    ev = unifi.parse(find("VPN Client Connected|1|UNIFIcategory=VPN UNIFIhost=CTS SG UNIFIwanId=WAN1 src=11.14.14.147"),
                     "Asia/Singapore", NOW)
    assert (ev.category, ev.action, ev.src_ip, ev.user_name) == ("vpn", "vpn-user-connect", "11.14.14.147",
                                                                 "Kevin Henry Tan's Desktop")
    assert ev.extra["assigned_ip"] == "192.168.11.13" and ev.interface == "CTSSG"
