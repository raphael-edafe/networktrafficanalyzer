"""Live web dashboard. Reads straight from the SQLite DB the analyser writes,
polls /api/state every few seconds, and renders charts with Chart.js.

    python dashboard.py            # then open http://127.0.0.1:5000
"""
import os

from flask import Flask, jsonify, render_template_string

from netanalyser.config import Config
from netanalyser.storage import Storage

CONFIG_PATH = os.environ.get("NETANALYSER_CONFIG", "config.json")
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
    return render_template_string(PAGE)


PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Network Traffic Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <style>
    :root { --bg:#1e1e1e; --panel:#252526; --line:#3a3a3a; --teal:#4ec9b0;
            --warn:#e5c07b; --crit:#f44747; --muted:#888; }
    body { font-family: ui-monospace, Consolas, monospace; background:var(--bg);
           color:#ddd; padding:20px; margin:0; }
    h1 { color:var(--teal); margin:0 0 4px; }
    .sub { color:var(--muted); font-size:.85em; margin-bottom:16px; }
    .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
    .card { background:var(--panel); border:1px solid var(--line); border-radius:8px;
            padding:14px 18px; min-width:120px; }
    .card .n { font-size:1.8em; font-weight:bold; }
    .card .l { color:var(--muted); font-size:.8em; text-transform:uppercase; }
    .card.crit .n { color:var(--crit); } .card.warn .n { color:var(--warn); }
    .card.ok .n { color:var(--teal); }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    .panel h2 { margin:0 0 12px; font-size:1em; color:var(--teal); }
    table { border-collapse:collapse; width:100%; font-size:.85em; }
    th,td { border-bottom:1px solid var(--line); padding:6px 8px; text-align:left; }
    th { color:var(--muted); font-weight:normal; }
    .alert { padding:6px 10px; margin:4px 0; border-left:4px solid var(--line);
             font-size:.85em; border-radius:0 4px 4px 0; }
    .INFO { color:var(--muted); border-left-color:#555; }
    .WARNING { color:var(--warn); border-left-color:var(--warn); }
    .CRITICAL { color:var(--crit); border-left-color:var(--crit); font-weight:bold; }
    .cat { display:inline-block; min-width:120px; opacity:.8; }
    .full { grid-column:1 / -1; }
    canvas { max-height:240px; }
  </style>
</head>
<body>
  <h1>Network Traffic Dashboard</h1>
  <div class="sub">Last window: <span id="updated">…</span> · auto-refresh 3s</div>

  <div class="cards">
    <div class="card ok"><div class="n" id="c-active">–</div><div class="l">Active peers</div></div>
    <div class="card"><div class="n" id="c-known">–</div><div class="l">Known IPs</div></div>
    <div class="card warn"><div class="n" id="c-warn">–</div><div class="l">Warnings</div></div>
    <div class="card crit"><div class="n" id="c-crit">–</div><div class="l">Critical</div></div>
  </div>

  <div class="grid">
    <div class="panel full"><h2>Traffic over time (packets / window)</h2><canvas id="ts"></canvas></div>
    <div class="panel"><h2>Top talkers (bytes)</h2><canvas id="talkers"></canvas></div>
    <div class="panel"><h2>Alerts by severity</h2><canvas id="sev"></canvas></div>

    <div class="panel">
      <h2>Current window — active peers</h2>
      <table><thead><tr><th>IP</th><th>Pkts</th><th>In</th><th>Out</th></tr></thead>
      <tbody id="cur"></tbody></table>
    </div>
    <div class="panel">
      <h2>Recent alerts</h2>
      <div id="alerts"></div>
    </div>
  </div>

<script>
const COL = { CRITICAL:'#f44747', WARNING:'#e5c07b', INFO:'#888' };
let tsChart, talkChart, sevChart;

function mkLine(ctx){ return new Chart(ctx,{type:'line',
  data:{labels:[],datasets:[{label:'packets',data:[],borderColor:'#4ec9b0',
    backgroundColor:'rgba(78,201,176,.15)',fill:true,tension:.3,pointRadius:0}]},
  options:{plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#888',maxTicksLimit:8}},
    y:{ticks:{color:'#888'},grid:{color:'#3a3a3a'}}}}}); }
function mkBar(ctx){ return new Chart(ctx,{type:'bar',
  data:{labels:[],datasets:[{data:[],backgroundColor:'#4ec9b0'}]},
  options:{indexAxis:'y',plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:'#888'},grid:{color:'#3a3a3a'}},y:{ticks:{color:'#ddd'}}}}}); }
function mkDoughnut(ctx){ return new Chart(ctx,{type:'doughnut',
  data:{labels:[],datasets:[{data:[],backgroundColor:[]}]},
  options:{plugins:{legend:{labels:{color:'#ddd'}}}}}); }

function esc(s){ return (s||'').replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

async function refresh(){
  let s; try { s = await (await fetch('/api/state')).json(); } catch(e){ return; }
  document.getElementById('updated').textContent = s.summary.last_updated;
  document.getElementById('c-active').textContent = s.summary.active_ips;
  document.getElementById('c-known').textContent = s.summary.known_ips;
  document.getElementById('c-warn').textContent = s.summary.warning;
  document.getElementById('c-crit').textContent = s.summary.critical;

  tsChart.data.labels = s.timeseries.labels;
  tsChart.data.datasets[0].data = s.timeseries.packets;
  tsChart.update();

  talkChart.data.labels = s.top_talkers.map(t=>t.ip);
  talkChart.data.datasets[0].data = s.top_talkers.map(t=>t.bytes);
  talkChart.update();

  const sv = s.severity;
  sevChart.data.labels = Object.keys(sv);
  sevChart.data.datasets[0].data = Object.values(sv);
  sevChart.data.datasets[0].backgroundColor = Object.keys(sv).map(k=>COL[k]||'#888');
  sevChart.update();

  document.getElementById('cur').innerHTML = s.current.map(r=>
    `<tr><td>${esc(r.ip)}</td><td>${r.packet_count}</td><td>${r.bytes_in}</td><td>${r.bytes_out}</td></tr>`
  ).join('') || '<tr><td colspan=4>No traffic yet.</td></tr>';

  document.getElementById('alerts').innerHTML = s.alerts.map(a=>
    `<div class="alert ${a.severity}"><span class="cat">[${esc(a.category)}]</span>`+
    `${a.ts.slice(11)} — ${esc(a.message)}</div>`
  ).join('') || '<p>No alerts yet.</p>';
}

window.onload = () => {
  tsChart = mkLine(document.getElementById('ts'));
  talkChart = mkBar(document.getElementById('talkers'));
  sevChart = mkDoughnut(document.getElementById('sev'));
  refresh(); setInterval(refresh, 3000);
};
</script>
</body>
</html>
"""

if __name__ == "__main__":
    # Debug mode exposes Werkzeug's interactive debugger (an RCE vector), so it's OFF
    # by default. Opt in for local development with NETANALYSER_DEBUG=1.
    debug = os.environ.get("NETANALYSER_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host="127.0.0.1", port=5000, debug=debug)
