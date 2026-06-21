"""SQLite persistence.

Replaces the old in-memory baselines + dashboard_state.json hand-off:
  * baselines (known IPs, per-IP packet history, beacon contacts) survive restarts
  * the dashboard reads the same DB, so there's no racy JSON file
WAL mode lets the dashboard read while the sniffer writes.
"""
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS known_ips (
    ip          TEXT PRIMARY KEY,
    first_seen  TEXT,
    last_seen   TEXT,
    country     TEXT,
    org         TEXT,
    lat         REAL,
    lon         REAL,
    malicious   INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS windows (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts    TEXT,
    epoch REAL
);
CREATE TABLE IF NOT EXISTS traffic (
    window_id    INTEGER,
    ip           TEXT,
    packet_count INTEGER,
    byte_count   INTEGER,
    bytes_in     INTEGER,
    bytes_out    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_traffic_ip ON traffic(ip);
CREATE INDEX IF NOT EXISTS idx_traffic_window ON traffic(window_id);
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT,
    epoch      REAL,
    severity   TEXT,
    category   TEXT,
    ip         TEXT,
    message    TEXT,
    confidence REAL
);
CREATE TABLE IF NOT EXISTS beacon_contacts (
    peer  TEXT,
    epoch REAL
);
CREATE INDEX IF NOT EXISTS idx_beacon_peer ON beacon_contacts(peer);
"""


class Storage:
    def __init__(self, path: str = "netanalyser.db"):
        # check_same_thread=False so the Flask dashboard can share a connection if needed.
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- baselines ----------------------------------------------------------
    def known_ip_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM known_ips").fetchone()[0]

    def get_known_ip(self, ip):
        return self.conn.execute("SELECT * FROM known_ips WHERE ip=?", (ip,)).fetchone()

    def upsert_known_ip(self, ip, ts, country=None, org=None, lat=None, lon=None, malicious=0):
        self.conn.execute(
            """INSERT INTO known_ips (ip, first_seen, last_seen, country, org, lat, lon, malicious)
                 VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 country=COALESCE(excluded.country, known_ips.country),
                 org=COALESCE(excluded.org, known_ips.org),
                 lat=COALESCE(excluded.lat, known_ips.lat),
                 lon=COALESCE(excluded.lon, known_ips.lon),
                 malicious=MAX(excluded.malicious, known_ips.malicious)""",
            (ip, ts, ts, country, org, lat, lon, malicious),
        )
        self.conn.commit()

    # ---- windows + traffic --------------------------------------------------
    def add_window(self, ts: str, epoch: float) -> int:
        cur = self.conn.execute("INSERT INTO windows (ts, epoch) VALUES (?,?)", (ts, epoch))
        self.conn.commit()
        return cur.lastrowid

    def add_traffic(self, window_id, rec):
        self.conn.execute(
            "INSERT INTO traffic VALUES (?,?,?,?,?,?)",
            (window_id, rec.ip, rec.packet_count, rec.byte_count, rec.bytes_in, rec.bytes_out),
        )
        self.conn.commit()

    def get_ip_packet_history(self, ip: str, limit: int):
        rows = self.conn.execute(
            "SELECT packet_count FROM traffic WHERE ip=? ORDER BY window_id DESC LIMIT ?",
            (ip, limit),
        ).fetchall()
        return [r[0] for r in rows]

    # ---- beaconing ----------------------------------------------------------
    def add_beacon_contact(self, peer: str, epoch: float, keep: int):
        self.conn.execute("INSERT INTO beacon_contacts VALUES (?,?)", (peer, epoch))
        # Trim to the most recent `keep` contacts for this peer.
        self.conn.execute(
            """DELETE FROM beacon_contacts
                WHERE peer=? AND rowid NOT IN (
                    SELECT rowid FROM beacon_contacts WHERE peer=? ORDER BY epoch DESC LIMIT ?)""",
            (peer, peer, keep),
        )
        self.conn.commit()

    def get_beacon_contacts(self, peer: str):
        rows = self.conn.execute(
            "SELECT epoch FROM beacon_contacts WHERE peer=? ORDER BY epoch", (peer,)
        ).fetchall()
        return [r[0] for r in rows]

    # ---- alerts -------------------------------------------------------------
    def add_alert(self, ts, epoch, severity, category, ip, message, confidence=None):
        self.conn.execute(
            "INSERT INTO alerts (ts, epoch, severity, category, ip, message, confidence) VALUES (?,?,?,?,?,?,?)",
            (ts, epoch, severity, category, ip, message, confidence),
        )
        self.conn.commit()

    # ---- dashboard read queries --------------------------------------------
    def latest_window(self):
        return self.conn.execute("SELECT * FROM windows ORDER BY id DESC LIMIT 1").fetchone()

    def latest_traffic(self):
        w = self.latest_window()
        if not w:
            return []
        return self.conn.execute(
            "SELECT * FROM traffic WHERE window_id=? ORDER BY byte_count DESC", (w["id"],)
        ).fetchall()

    def recent_alerts(self, limit=40):
        return self.conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def timeseries(self, limit=60):
        rows = self.conn.execute(
            """SELECT w.ts AS ts, SUM(t.packet_count) AS packets, SUM(t.byte_count) AS bytes
                 FROM windows w JOIN traffic t ON t.window_id=w.id
                GROUP BY w.id ORDER BY w.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return list(reversed(rows))

    def top_talkers(self, limit=8):
        return self.conn.execute(
            "SELECT ip, SUM(byte_count) AS bytes FROM traffic GROUP BY ip ORDER BY bytes DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def severity_counts(self):
        return {r["severity"]: r["n"]
                for r in self.conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity").fetchall()}

    def country_counts(self, limit=10):
        return self.conn.execute(
            """SELECT country, COUNT(*) AS n FROM known_ips
                WHERE country IS NOT NULL AND country != ''
                GROUP BY country ORDER BY n DESC LIMIT ?""",
            (limit,),
        ).fetchall()

    def geo_points(self):
        return self.conn.execute(
            """SELECT ip, lat, lon, country, org, malicious FROM known_ips
                WHERE lat IS NOT NULL AND lon IS NOT NULL"""
        ).fetchall()

    def summary(self):
        sev = self.severity_counts()
        latest = self.latest_window()
        active = 0
        if latest:
            active = self.conn.execute(
                "SELECT COUNT(*) FROM traffic WHERE window_id=?", (latest["id"],)).fetchone()[0]
        return {
            "total_alerts": sum(sev.values()),
            "critical": sev.get("CRITICAL", 0),
            "warning": sev.get("WARNING", 0),
            "known_ips": self.known_ip_count(),
            "active_ips": active,
            "last_updated": latest["ts"] if latest else "Never",
        }

    def close(self):
        self.conn.close()


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
