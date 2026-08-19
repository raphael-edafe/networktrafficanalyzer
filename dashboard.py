"""Live web dashboard. Reads straight from the SQLite DB the analyser writes,
polls /api/state every few seconds, and draws everything in ASCII - block
sparkline, bracket bars - so the page pulls in no charting library and has
no external dependency at all.

    python dashboard.py            # then open http://127.0.0.1:5000
"""
import importlib
import os
import sys

from flask import Flask, jsonify

# 'net-analyzer' has a hyphen, so normal import syntax won't work — use importlib.
sys.modules['net_analyzer'] = importlib.import_module('net-analyzer')
from net_analyzer.config import Config
from net_analyzer.storage import Storage

CONFIG_PATH = os.environ.get("NET_ANALYZER_CONFIG", "config.json")
cfg = Config.load(CONFIG_PATH)
app = Flask(__name__)


def _db():
    # One short-lived connection per request keeps Flask's threading happy.
    return Storage(cfg.db_file)


def rows(rs):
    return [dict(r) for r in rs]


@app.route("/api/state")
def state():
    db = _db()
    try:
        ts = db.timeseries(60)
        sev = db.severity_counts()
        return jsonify({
            "summary": db.summary(),
            "current": rows(db.latest_traffic()),
            "alerts": rows(db.recent_alerts(40)),
            "timeseries": {
                "labels": [r["ts"][11:] for r in ts],
                "packets": [r["packets"] for r in ts],
                "bytes": [r["bytes"] for r in ts],
            },
            "top_talkers": rows(db.top_talkers(8)),
            "severity": sev,
            "countries": rows(db.country_counts(10)),
        })
    finally:
        db.close()


@app.route("/")
def dashboard():
    # returned directly rather than through render_template_string: there
    # are no template variables, and Jinja would otherwise try to parse
    # any {{ or {% that happened to form inside the page JS
    return PAGE


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>net-analyzer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:     #07090a;
  --panel:  #0d1011;
  --raised: #131718;
  --rule:   #1e2426;
  --rule-2: #2c3436;
  --dim:    #5c6b6d;
  --mid:    #8b9b9c;
  --text:   #c3d1cf;
  --bright: #eaf2ef;

  /* accent matches the sibling project; amber and red are reserved for
     severity, so a colour on this page always means something */
  --accent: #5f9ec9;
  --wire:   #7fb4d6;
  --info:   #8b9b9c;
  --warn:   #cc9166;
  --crit:   #c2635e;

  --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

/* JetBrains Mono draws -> => != as single glyphs. Hostnames, paths and alert
   text contain those sequences and are shown verbatim, so the font must not
   redraw them. */
* { box-sizing: border-box; font-variant-ligatures: none;
    font-feature-settings: "liga" 0, "clig" 0, "calt" 0; }

body {
  margin: 0; padding: 26px 20px 80px;
  background: var(--bg); color: var(--text);
  font: 400 13px/1.6 var(--mono);
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1400px; margin: 0 auto; }

/* ---- wire: packets travelling, same mechanic as the sibling project's fish.
   CSS rather than JS because a negative animation-delay starts each packet
   part-way along, so the wire is populated the moment the page loads. ---- */
.line { position: relative; height: 16px; overflow: hidden; font-size: 12px; line-height: 16px; }
.pkt { position: absolute; top: 0; white-space: pre; color: var(--wire);
       animation: travel linear infinite; }
.pkt.back { animation-name: travel-back; }
@keyframes travel      { from { left: -5ch; } to { left: 100%; } }
@keyframes travel-back { from { left: 100%; } to { left: -5ch; } }
.p1 { animation-duration: 19s; animation-delay:  -3s; }
.p2 { animation-duration: 27s; animation-delay: -14s; opacity: .7; }
.p3 { animation-duration: 23s; animation-delay: -19s; opacity: .85; }
.p4 { animation-duration: 33s; animation-delay:  -8s; opacity: .6; }
.p5 { animation-duration: 16s; animation-delay: -11s; }
@media (prefers-reduced-motion: reduce) {
  .pkt { animation: none; }
  .p1 { left: 5%; } .p2 { left: 27%; } .p3 { left: 48%; }
  .p4 { left: 69%; } .p5 { left: 88%; }
}
.rail { color: var(--dim); white-space: pre; overflow: hidden; margin: 0; font-size: 12px; }

.title { color: var(--bright); font-weight: 700; font-size: 19px;
         letter-spacing: .16em; margin: 12px 0 5px; }
.sub { color: var(--mid); margin: 0 0 22px; }
.sub .live { color: var(--accent); }

/* ---- boxes ---- */
.box { border: 1px solid var(--rule); background: var(--panel); margin-bottom: 16px; }
.box > .bar { border-bottom: 1px solid var(--rule); padding: 7px 12px;
              color: var(--mid); display: flex; align-items: center; gap: 10px; }
.box > .bar .k { color: var(--accent); }
.box > .bar .sp { flex: 1; }
.box > .bar .meta { color: var(--dim); font-size: 12px; }
.box > .in { padding: 12px; overflow-x: auto; }

.grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
@media (min-width: 1080px) { .grid { grid-template-columns: 1fr 1fr; }
                             .grid .full { grid-column: 1 / -1; } }

/* ---- status counters ---- */
.counts { display: flex; flex-wrap: wrap; gap: 26px; }
.count .n { font-size: 22px; font-weight: 700; line-height: 1.2; }
.count .l { color: var(--dim); font-size: 12px; letter-spacing: .06em; }
.count.ok   .n { color: var(--accent); }
.count.warn .n { color: var(--warn); }
.count.crit .n { color: var(--crit); }

/* ---- ascii charts ---- */
.spark { white-space: pre; color: var(--accent); font-size: 26px; line-height: 1.05;
         margin: 0; overflow-x: auto; }
.axis { display: flex; color: var(--dim); font-size: 11.5px; margin-top: 6px; }
.axis .sp { flex: 1; }

.bars { margin: 0; }
.bar-row { display: flex; align-items: baseline; gap: 10px; padding: 3px 0;
           border-bottom: 1px dotted var(--rule); }
.bar-row:last-child { border-bottom: 0; }
.bar-row .lbl { flex: none; width: 15ch; color: var(--text);
                overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-row .g { white-space: pre; color: var(--accent); }
.bar-row .g .rest { color: var(--rule-2); }
.bar-row .v { margin-left: auto; color: var(--mid); flex: none; }
.bar-row.CRITICAL .g { color: var(--crit); }
.bar-row.WARNING  .g { color: var(--warn); }
.bar-row.INFO     .g { color: var(--info); }

/* ---- tables ---- */
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 4px 10px 4px 0; border-bottom: 1px dotted var(--rule); }
th { color: var(--dim); font-weight: 500; }
td { color: var(--text); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }

/* ---- alerts ---- */
.alerts { margin: 0; }
.al { display: flex; gap: 10px; padding: 4px 0; border-bottom: 1px dotted var(--rule); }
.al:last-child { border-bottom: 0; }
.al .sev { flex: none; width: 3ch; font-weight: 700; }
.al .cat { flex: none; width: 17ch; color: var(--dim); }
.al .ts  { flex: none; color: var(--dim); }
.al .msg { color: var(--text); }
.al.CRITICAL .sev { color: var(--crit); }
.al.WARNING  .sev { color: var(--warn); }
.al.INFO     .sev { color: var(--info); }
.empty { color: var(--dim); margin: 0; }
</style>
</head>
<body>
<div class="wrap">

  <div class="line" aria-hidden="true">
    <span class="pkt p1">&gt;--o</span>
    <span class="pkt p2 back">o--&lt;</span>
    <span class="pkt p3">&gt;--o</span>
    <span class="pkt p4 back">o--&lt;</span>
    <span class="pkt p5">&gt;--o</span>
  </div>
  <pre class="rail" id="rail"></pre>

  <div class="title">NET-ANALYZER</div>
  <p class="sub">live capture <span class="live">&gt;--o</span>
     last window <span id="updated">...</span> · refreshing every 3s</p>

  <div class="box">
    <div class="bar"><span class="k">$</span> status <span class="sp"></span>
      <span class="meta" id="totals"></span></div>
    <div class="in">
      <div class="counts">
        <div class="count ok"><div class="n" id="c-active">-</div><div class="l">active peers</div></div>
        <div class="count"><div class="n" id="c-known">-</div><div class="l">known ips</div></div>
        <div class="count warn"><div class="n" id="c-warn">-</div><div class="l">warnings</div></div>
        <div class="count crit"><div class="n" id="c-crit">-</div><div class="l">critical</div></div>
      </div>
    </div>
  </div>

  <div class="grid">
    <div class="box full">
      <div class="bar"><span class="k">&gt;</span> traffic over time <span class="sp"></span>
        <span class="meta">packets per window</span></div>
      <div class="in">
        <pre class="spark" id="spark"></pre>
        <div class="axis"><span id="ax-from"></span><span class="sp"></span>
          <span id="ax-peak"></span><span class="sp"></span><span id="ax-to"></span></div>
      </div>
    </div>

    <div class="box">
      <div class="bar"><span class="k">&gt;</span> top talkers <span class="sp"></span>
        <span class="meta">bytes</span></div>
      <div class="in"><div class="bars" id="talkers"></div></div>
    </div>

    <div class="box">
      <div class="bar"><span class="k">&gt;</span> alerts by severity</div>
      <div class="in"><div class="bars" id="sev"></div></div>
    </div>

    <div class="box">
      <div class="bar"><span class="k">&gt;</span> current window <span class="sp"></span>
        <span class="meta">active peers</span></div>
      <div class="in">
        <table><thead><tr><th>ip</th><th class="num">pkts</th>
          <th class="num">in</th><th class="num">out</th></tr></thead>
          <tbody id="cur"></tbody></table>
      </div>
    </div>

    <div class="box">
      <div class="bar"><span class="k">&gt;</span> recent alerts</div>
      <div class="in"><div class="alerts" id="alerts"></div></div>
    </div>
  </div>

<pre class="rail" id="rail2"></pre>
</div>

<script>
const $ = s => document.querySelector(s);
const esc = s => (s || '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const el = (t, c, txt) => { const n = document.createElement(t); if (c) n.className = c;
                            if (txt != null) n.textContent = txt; return n; };

// the rails are drawn to the container width rather than a fixed length, so
// packets never travel past the end of the wire
function drawRails() {
  const probe = el('span'); probe.style.cssText =
    'position:absolute;visibility:hidden;white-space:pre;font:' + getComputedStyle($('#rail')).font;
  probe.textContent = '-'.repeat(100); document.body.append(probe);
  const chw = probe.getBoundingClientRect().width / 100; probe.remove();
  const n = Math.ceil($('.wrap').clientWidth / (chw || 7)) + 2;
  const rail = '-'.repeat(n);
  $('#rail').textContent = rail;
  $('#rail2').textContent = rail;
}

function human(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

// block characters give eight levels of resolution per cell, which is enough
// to read a traffic curve without pulling in a charting library
const BLOCKS = ['▁','▂','▃','▄','▅','▆','▇','█'];
function sparkline(values) {
  if (!values.length) return '';
  const peak = Math.max(...values, 1);
  return values.map(v => BLOCKS[Math.min(7, Math.floor((v / peak) * 8 - 0.0001) + (v ? 0 : 0))] || BLOCKS[0]).join('');
}

// one bar builder for both charts: a filled run and a dotted remainder, same
// shape as the risk meter in the sibling project
function barRow(label, value, max, display, cls) {
  const cells = 22;
  const on = max > 0 ? Math.max(1, Math.round((value / max) * cells)) : 0;
  const row = el('div', 'bar-row' + (cls ? ' ' + cls : ''));
  row.append(el('span', 'lbl', label));
  const g = el('span', 'g');
  g.append(document.createTextNode('['), el('span', 'on', '#'.repeat(on)),
           el('span', 'rest', '.'.repeat(cells - on)), document.createTextNode(']'));
  row.append(g, el('span', 'v', display));
  return row;
}

async function refresh() {
  let s;
  try { s = await (await fetch('/api/state')).json(); }
  catch (e) { return; }   // a failed poll is not worth clearing the screen for

  $('#updated').textContent = s.summary.last_updated;
  $('#totals').textContent = s.summary.total_alerts + ' alerts total';
  $('#c-active').textContent = s.summary.active_ips;
  $('#c-known').textContent = s.summary.known_ips;
  $('#c-warn').textContent = s.summary.warning;
  $('#c-crit').textContent = s.summary.critical;

  const pk = s.timeseries.packets, lb = s.timeseries.labels;
  $('#spark').textContent = sparkline(pk);
  $('#ax-from').textContent = lb[0] || '';
  $('#ax-peak').textContent = pk.length ? 'peak ' + Math.max(...pk) : '';
  $('#ax-to').textContent = lb[lb.length - 1] || '';

  const talkers = $('#talkers'); talkers.replaceChildren();
  const maxB = Math.max(...s.top_talkers.map(t => t.bytes), 1);
  s.top_talkers.forEach(t => talkers.append(barRow(t.ip, t.bytes, maxB, human(t.bytes))));
  if (!s.top_talkers.length) talkers.append(el('p', 'empty', 'no traffic yet'));

  const sev = $('#sev'); sev.replaceChildren();
  const order = ['CRITICAL', 'WARNING', 'INFO'];
  const maxS = Math.max(...Object.values(s.severity), 1);
  order.filter(k => k in s.severity).forEach(k =>
    sev.append(barRow(k.toLowerCase(), s.severity[k], maxS, String(s.severity[k]), k)));
  if (!Object.keys(s.severity).length) sev.append(el('p', 'empty', 'no alerts yet'));

  const cur = $('#cur'); cur.replaceChildren();
  s.current.forEach(r => {
    const tr = el('tr');
    tr.append(el('td', null, r.ip), el('td', 'num', String(r.packet_count)),
              el('td', 'num', human(r.bytes_in)), el('td', 'num', human(r.bytes_out)));
    cur.append(tr);
  });
  if (!s.current.length) {
    const tr = el('tr'); const td = el('td', null, 'no traffic yet');
    td.colSpan = 4; tr.append(td); cur.append(tr);
  }

  const al = $('#alerts'); al.replaceChildren();
  s.alerts.forEach(a => {
    const row = el('div', 'al ' + a.severity);
    row.append(el('span', 'sev', a.severity[0]),
               el('span', 'cat', '[' + a.category + ']'),
               el('span', 'ts', a.ts.slice(11)),
               el('span', 'msg', a.message));
    al.append(row);
  });
  if (!s.alerts.length) al.append(el('p', 'empty', 'no alerts yet'));
}

drawRails();
addEventListener('resize', drawRails);
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    # Debug mode exposes Werkzeug's interactive debugger (an RCE vector), so it's OFF
    # by default. Opt in for local development with NETANALYSER_DEBUG=1.
    debug = os.environ.get("NET_ANALYZER_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host="127.0.0.1", port=5000, debug=debug)
