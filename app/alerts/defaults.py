"""Default Event Monitor rules (global: apply to every client). Used by migration 0009 and by tests."""

RULE_TYPES = ("device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "config_change", "wan_failover",
              "outdated_firmware", "log_source_silent", "event_match", "ioc_match", "storage_quota", "wan_down", "internet_down",
              "isp_degraded", "server_health", "unifi_event", "vpn_disconnect", "ap_offline", "wifi_quality", "poe_issue")

DEFAULT_RULES = [
    ("Device offline", "device_offline", "high", {"minutes": 5}),
    ("VPN tunnel down", "vpn_tunnel_down", "high", {"minutes": 5}),
    ("VPN tunnel flapping", "vpn_flapping", "medium", {"drops": 10, "window_minutes": 60}),
    ("Repeated failed VPN/admin logins", "failed_logins", "high",
     {"count": 10, "window_minutes": 15, "exclude_actions": ["vpn-tls-error", "vpn-ike-no-proposal"]}),
    ("Configuration change", "config_change", "medium", {}),
    ("WAN IP changed (possible failover)", "wan_failover", "high", {}),
    ("Outdated firmware", "outdated_firmware", "low", {}),
    ("Log source silent", "log_source_silent", "medium", {"minutes": 30}),
]

# Added by later migrations (kept separate so migration 0009 only inserts types its constraint allows).
LATER_RULES = [
    ("Threat intel match", "ioc_match", "high", {}),   # migration 0011
    ("Storage quota", "storage_quota", "medium", {"warn_pct": 80}),   # migration 0012
    ("Internet down", "internet_down", "critical", {"minutes": 2}),     # migration 0014
    ("WAN interface down", "wan_down", "high", {"minutes": 2}),         # migration 0014
    ("Internet degraded (loss / latency)", "isp_degraded", "medium", {"loss_pct": 5, "latency_ms": 150, "periods": 3}),  # 0024
    ("Log server health", "server_health", "high",
     {"stall_minutes": 10, "backlog": 200000, "disk_pct": 85, "backup_hours": 26, "poll_fail_pct": 50}),   # 0031
    ("Gateway events (immediate)", "unifi_event", "high", {"event_ids": [539, 568]}),   # 0032 (524 -> 0034, 105 -> 0037)
    ("Site-to-site VPN disconnected", "vpn_disconnect", "high", {"hours": 24, "min_seconds": 60}),   # 0034
    ("Internet failover (secondary WAN)", "unifi_event", "high", {"event_ids": [105]}),   # 0037
    ("VPN port scans (handshake failures)", "failed_logins", "medium",
     {"count": 10, "window_minutes": 15, "actions": ["vpn-tls-error", "vpn-ike-no-proposal"]}),   # 0040
    ("Access point offline", "ap_offline", "high", {"minutes": 5, "ignore_after_days": 7}),   # 0041
    ("Wi-Fi quality (interference / weak signal)", "wifi_quality", "medium",
     {"minutes": 15, "utilisation_pct": 80, "experience_pct": 60, "weak_dbm": -75, "weak_clients": 2}),   # 0041
    ("PoE problem (low power / budget / fault)", "poe_issue", "medium", {"budget_pct": 90}),   # 0041
]
