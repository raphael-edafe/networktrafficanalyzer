"""Config loading with validation and sane defaults for all the v2 features."""
import json
from dataclasses import dataclass, field
from typing import List


DEFAULTS = {
    # --- core ---
    "my_ip": None,
    "window_seconds": 10,
    "log_file": "alerts.log",
    "db_file": "netanalyser.db",
    "ignored_ips": [],
    "suspicious_ports": [21, 23, 445, 3389, 5900],
    "trusted_org_keywords": ["microsoft", "google", "amazon", "cloudflare", "akamai", "apple"],

    # --- volume anomaly (robust modified z-score) ---
    "anomaly_z_threshold": 3.5,
    "anomaly_min_samples": 4,
    "anomaly_min_packets": 50,       # absolute floor: ignore "spikes" smaller than this
    "volume_threshold_multiplier": 3,   # kept for backward-compat / display only

    # --- port scan ---
    "port_scan_threshold": 5,

    # --- beaconing / C2 ---
    # Real networks are full of periodic chatter (keepalives, telemetry), so beaconing
    # is treated as a WARNING to investigate — it's only upgraded to CRITICAL when the
    # peer is also on the threat blocklist. Beacons to trusted cloud orgs are suppressed.
    "beacon_min_hits": 6,            # minimum number of contacts before we judge periodicity
    "beacon_min_interval": 5.0,      # seconds; ignore very chatty flows
    "beacon_max_interval": 3600.0,   # seconds; ignore very slow flows
    "beacon_max_cv": 0.08,           # coefficient of variation: lower = more regular = more suspicious
    "beacon_history": 32,            # contacts retained per peer

    # --- data exfiltration ---
    "exfil_bytes_threshold": 5_000_000,   # outbound bytes to a single peer in one window

    # --- enrichment ---
    "enable_geo": True,
    "ipinfo_token": "",
    "threat_blocklist_file": "threat_blocklist.txt",
    "threat_blocklist_url": "",

    # --- alerting ---
    "alert_cooldown_seconds": 120,   # suppress identical (category, ip) alerts within this window
    "notify_webhook_url": "",
    "notify_min_severity": "CRITICAL",
}


@dataclass
class Config:
    my_ip: str
    window_seconds: int
    log_file: str
    db_file: str
    ignored_ips: set
    suspicious_ports: set
    trusted_org_keywords: List[str]
    anomaly_z_threshold: float
    anomaly_min_samples: int
    anomaly_min_packets: int
    volume_threshold_multiplier: float
    port_scan_threshold: int
    beacon_min_hits: int
    beacon_min_interval: float
    beacon_max_interval: float
    beacon_max_cv: float
    beacon_history: int
    exfil_bytes_threshold: int
    enable_geo: bool
    ipinfo_token: str
    threat_blocklist_file: str
    threat_blocklist_url: str
    alert_cooldown_seconds: int
    notify_webhook_url: str
    notify_min_severity: str

    @classmethod
    def from_dict(cls, raw: dict) -> "Config":
        merged = {**DEFAULTS, **raw}
        if not merged.get("my_ip"):
            raise ValueError("config: 'my_ip' is required (the IP of the host you're protecting)")
        if merged["window_seconds"] <= 0:
            raise ValueError("config: 'window_seconds' must be positive")
        merged["ignored_ips"] = set(merged["ignored_ips"])
        merged["suspicious_ports"] = set(int(p) for p in merged["suspicious_ports"])
        if merged["notify_min_severity"] not in ("INFO", "WARNING", "CRITICAL"):
            raise ValueError("config: 'notify_min_severity' must be INFO, WARNING or CRITICAL")
        # Drop any unknown keys so the dataclass init doesn't choke.
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in merged.items() if k in known})

    @classmethod
    def load(cls, path: str = "config.json") -> "Config":
        with open(path) as f:
            return cls.from_dict(json.load(f))
