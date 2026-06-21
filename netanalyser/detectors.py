"""Pure detection functions. No scapy, no I/O -> fast and trivially unit-testable."""
import statistics

from .models import Alert


def detect_suspicious_ports(rec, suspicious_ports):
    """Inbound connection to a sensitive service port (FTP/Telnet/RDP/SMB/VNC...)."""
    alerts = []
    for port in sorted(rec.ports & suspicious_ports):
        alerts.append(Alert(
            severity="CRITICAL", category="SUSPICIOUS_PORT",
            message=f"{rec.ip} connected to sensitive port {port} on this machine",
            ip=rec.ip,
        ))
    return alerts


def detect_port_scan(rec, threshold):
    """One peer touching many distinct ports = vertical port scan."""
    n = len(rec.ports)
    if n > threshold:
        return [Alert(
            severity="CRITICAL", category="PORT_SCAN",
            message=f"{rec.ip} contacted {n} distinct ports on this machine",
            ip=rec.ip,
        )]
    return []


def detect_volume_anomaly(rec, history, z_threshold, min_samples, min_packets=0):
    """Robust (median/MAD) modified z-score — resistant to the spikes we're hunting,
    unlike a plain mean which the spike itself would inflate. The absolute `min_packets`
    floor stops tiny baselines (e.g. 2 packets) from flagging an 11-packet 'spike'."""
    if len(history) < min_samples or rec.packet_count < min_packets:
        return []
    median = statistics.median(history)
    mad = statistics.median([abs(x - median) for x in history])
    if mad == 0:
        # No historical variation: fall back to a simple multiple of the median.
        if median > 0 and rec.packet_count > median * 3:
            return [Alert("WARNING", "VOLUME_SPIKE",
                          f"{rec.ip} sent {rec.packet_count} packets (baseline ~{median:.0f})",
                          ip=rec.ip)]
        return []
    z = 0.6745 * (rec.packet_count - median) / mad
    if z > z_threshold:
        return [Alert(
            severity="WARNING", category="VOLUME_SPIKE",
            message=f"{rec.ip} sent {rec.packet_count} packets "
                    f"(baseline ~{median:.0f}, modified z={z:.1f})",
            ip=rec.ip, confidence=round(min(z / (z_threshold * 2), 1.0), 2),
        )]
    return []


def detect_exfil(rec, threshold):
    """Large outbound transfer to a single external peer in one window."""
    if rec.bytes_out > threshold:
        mb = rec.bytes_out / 1_000_000
        return [Alert(
            severity="WARNING", category="EXFIL",
            message=f"Large outbound transfer: {mb:.1f} MB sent to {rec.ip} this window",
            ip=rec.ip,
        )]
    return []


def detect_beacon(peer, timestamps, cfg):
    """Periodic 'phone-home' detection — the signature of C2 malware.

    Looks at inter-contact intervals: a low coefficient of variation (std/mean)
    means highly regular timing, which legitimate human-driven traffic rarely has.
    """
    if len(timestamps) < cfg.beacon_min_hits:
        return None
    ts = sorted(timestamps)
    intervals = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
    if len(intervals) < cfg.beacon_min_hits - 1:
        return None
    mean = sum(intervals) / len(intervals)
    if mean < cfg.beacon_min_interval or mean > cfg.beacon_max_interval:
        return None
    std = statistics.pstdev(intervals)
    cv = std / mean if mean else 1.0
    if cv <= cfg.beacon_max_cv:
        confidence = round(max(0.0, 1.0 - cv / cfg.beacon_max_cv), 2)
        # Base severity is WARNING; the analyzer upgrades to CRITICAL if the peer is
        # also on the threat blocklist. A beacon on its own is "investigate", not "alarm".
        return Alert(
            severity="WARNING", category="BEACONING",
            message=f"Periodic beaconing to {peer}: every ~{mean:.0f}s "
                    f"over {len(ts)} contacts (jitter CV={cv:.2f})",
            ip=peer, confidence=confidence,
        )
    return None
