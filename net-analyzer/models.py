"""Shared data types. Deliberately free of scapy so detectors stay unit-testable."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FlowRecord:
    """Aggregated stats for one peer (the non-local end of a conversation) in a window."""
    ip: str
    is_local: bool = False
    packet_count: int = 0
    byte_count: int = 0
    bytes_in: int = 0          # bytes this peer sent us
    bytes_out: int = 0         # bytes we sent this peer
    ports: set = field(default_factory=set)   # distinct dst ports this peer hit on the local host


# Severity ordering for thresholds/notifications.
SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}


@dataclass
class Alert:
    severity: str          # INFO | WARNING | CRITICAL
    category: str          # PORT_SCAN | BEACONING | EXFIL | ...
    message: str
    ip: Optional[str] = None
    confidence: Optional[float] = None

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)
