"""Generate a static demo page from the live dashboard.

    python build_demo.py     ->  docs/index.html

The demo is BUILT from dashboard.py's own template rather than maintained as a
copy, so the two cannot drift apart. Every change to the real dashboard lands
in the demo the next time this runs.

The dashboard already renders entirely client-side from one /api/state payload,
so a recorded snapshot can be dropped in where the fetch would go. Everything
still works - the sparkline, the bars, the alert list - with no server, no
database and no capture running behind it.

It is labelled as a recorded snapshot rather than live. A dashboard that lets a
reader assume traffic is moving when it is not would be misrepresenting what
they are looking at.
"""

import importlib
import json
import os
import pathlib
import sys

sys.modules["net_analyzer"] = importlib.import_module("net-analyzer")
from net_analyzer.config import Config
from net_analyzer.storage import Storage

OUT_DIR = pathlib.Path("docs")


def snapshot(cfg: Config) -> dict:
    """The same payload /api/state serves, built directly from the database."""
    db = Storage(cfg.db_file)
    try:
        ts = db.timeseries(60)
        return {
            "summary": db.summary(),
            "current": [dict(r) for r in db.latest_traffic()],
            "alerts": [dict(r) for r in db.recent_alerts(40)],
            "timeseries": {
                "labels": [r["ts"][11:] for r in ts],
                "packets": [r["packets"] for r in ts],
                "bytes": [r["bytes"] for r in ts],
            },
            "top_talkers": [dict(r) for r in db.top_talkers(8)],
            "severity": db.severity_counts(),
            "countries": [dict(r) for r in db.country_counts(10)],
        }
    finally:
        db.close()


def main() -> None:
    cfg = Config.load(os.environ.get("NET_ANALYZER_CONFIG", "config.json"))
    state = snapshot(cfg)
    if not state["current"] and not state["alerts"]:
        raise SystemExit(f"{cfg.db_file} has no traffic or alerts to show")

    import dashboard
    html = dashboard.PAGE

    # the poll becomes a lookup. refresh() is left otherwise untouched, so the
    # demo exercises exactly the same rendering path as the real dashboard.
    old = """  let s;
  try { s = await (await fetch('/api/state')).json(); }
  catch (e) { return; }   // a failed poll is not worth clearing the screen for
"""
    new = """  // recorded snapshot standing in for the poll - same payload, same shape
  const s = SNAPSHOT;
"""
    assert old in html, "refresh() fetch block not found - dashboard.py changed?"
    html = html.replace(old, new, 1)

    # no point re-rendering identical data every three seconds
    html = html.replace("refresh();\nsetInterval(refresh, 3000);", "refresh();", 1)

    html = html.replace("<script>", "<script>\nconst SNAPSHOT = " + json.dumps(state) + ";", 1)

    # say what it is, in the line that currently claims a live refresh
    html = html.replace(
        '''live capture <span class="live">[SYN]</span>
     last window <span id="updated">...</span> · refreshing every 3s''',
        '''recorded snapshot <span class="live">[SYN]</span>
     captured <span id="updated">...</span> · static page, nothing is capturing''', 1)

    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "index.html").write_text(html, encoding="utf-8")

    print(f"wrote {OUT_DIR / 'index.html'} ({len(html):,} bytes)")
    s = state["summary"]
    print(f"  {s['active_ips']} active peers, {s['known_ips']} known ips, "
          f"{s['warning']} warnings, {s['critical']} critical")
    print(f"  {len(state['alerts'])} alerts, {len(state['top_talkers'])} talkers, "
          f"{len(state['timeseries']['labels'])} windows")


if __name__ == "__main__":
    main()
