#!/usr/bin/env python3
"""IP Scanner Pro — web interface (no external dependencies)."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import scanner as sc

HTML = r"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Scanner Pro</title>
<style>
  .tabs { display:flex; gap:4px; margin-bottom:24px; }
  .tab  { padding:8px 20px; border-radius:6px; cursor:pointer; border:1px solid var(--border);
          color:var(--muted); background:var(--surface); font-family:var(--font); font-size:13px; }
  .tab.active { background:var(--accent); color:#fff; border-color:var(--accent); }
  .panel { display:none; }
  .panel.active { display:block; }
  .host-row { display:flex; align-items:center; justify-content:space-between;
              padding:10px 14px; border-bottom:1px solid #1e2130; }
  .host-row:last-child { border-bottom:none; }
  .host-ip   { font-weight:600; color:var(--green); }
  .host-name { color:var(--muted); font-size:12px; }
  .btn-scan-host { background:#1e2130; color:var(--accent); border:1px solid var(--border);
                   font-family:var(--font); font-size:12px; padding:5px 14px;
                   border-radius:5px; cursor:pointer; }
  .btn-scan-host:hover { background:var(--accent); color:#fff; }
</style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3e;
    --accent: #6c8ef5; --green: #4ade80; --red: #f87171;
    --yellow: #fbbf24; --text: #e2e8f0; --muted: #64748b;
    --font: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         font-size: 14px; min-height: 100vh; }
  header { background: var(--surface); border-bottom: 1px solid var(--border);
            padding: 20px 32px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 20px; color: var(--accent); letter-spacing: 1px; }
  header span { color: var(--muted); font-size: 12px; }
  main { max-width: 900px; margin: 40px auto; padding: 0 24px; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: 10px; padding: 28px; margin-bottom: 24px; }
  label { display: block; color: var(--muted); font-size: 12px;
          text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
  input { width: 100%; background: var(--bg); border: 1px solid var(--border);
          color: var(--text); font-family: var(--font); font-size: 14px;
          padding: 10px 14px; border-radius: 6px; outline: none;
          transition: border-color .2s; }
  input:focus { border-color: var(--accent); }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  button { background: var(--accent); color: #fff; border: none; cursor: pointer;
           font-family: var(--font); font-size: 14px; font-weight: 600;
           padding: 11px 32px; border-radius: 6px; transition: opacity .2s; }
  button:hover { opacity: .85; }
  button:disabled { opacity: .4; cursor: not-allowed; }
  .hint { color: var(--muted); font-size: 12px; margin-top: 6px; }
  #status { color: var(--yellow); min-height: 22px; margin-top: 12px; }
  table { width: 100%; border-collapse: collapse; }
  th { color: var(--muted); font-size: 11px; text-transform: uppercase;
       letter-spacing: 1px; padding: 8px 12px; text-align: left;
       border-bottom: 1px solid var(--border); }
  td { padding: 9px 12px; border-bottom: 1px solid #1e2130; font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  .open  { color: var(--green); font-weight: 600; }
  .closed{ color: var(--muted); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
           font-size: 11px; font-weight: 600; }
  .badge-open   { background: #14532d; color: var(--green); }
  .badge-closed { background: #1e2130; color: var(--muted); }
  .os-row { display: flex; gap: 32px; margin-bottom: 20px; flex-wrap: wrap; }
  .os-item label { margin-bottom: 2px; }
  .os-item span  { font-size: 15px; }
  .export-row { display: flex; gap: 10px; margin-top: 16px; }
  .btn-export { background: #1e2130; color: var(--accent); border: 1px solid var(--border);
                font-size: 12px; padding: 6px 16px; }
  .summary { display: flex; gap: 24px; margin-bottom: 20px; }
  .stat { display: flex; flex-direction: column; }
  .stat-val { font-size: 28px; font-weight: 700; }
  .stat-lbl { font-size: 11px; color: var(--muted); text-transform: uppercase;
              letter-spacing: 1px; }
  .open-val  { color: var(--green); }
  .total-val { color: var(--accent); }
</style>
</head>
<body>
<header>
  <h1>⬡ IP Scanner Pro</h1>
  <span>TCP port scanner · OS detection · JSON/CSV export</span>
</header>
<main>
  <div class="tabs">
    <button class="tab active" onclick="switchTab('scan')">Skan portów</button>
    <button class="tab"        onclick="switchTab('discover')">Odkryj sieć</button>
  </div>

  <!-- PANEL: skan portów -->
  <div class="panel active" id="panel-scan">
  <div class="card">
    <div class="row">
      <div>
        <label>IP / Hostname</label>
        <input id="host" type="text" placeholder="192.168.1.31" value="192.168.1.31">
      </div>
      <div>
        <label>Ports</label>
        <input id="ports" type="text" placeholder="7799,5055,8123,1984,5050" value="7799,5055,8123,1984,5050">
        <div class="hint">single · lista (80,443) · zakres (1-1024) · "common"</div>
      </div>
    </div>
    <div class="row">
      <div>
        <label>Timeout (s)</label>
        <input id="timeout" type="number" value="1.0" step="0.5" min="0.1" max="10">
      </div>
      <div>
        <label>Wątki</label>
        <input id="threads" type="number" value="100" min="1" max="500">
      </div>
    </div>
    <button id="scanBtn" onclick="startScan()">Skanuj</button>
    <div id="status"></div>
  </div>

  </div> <!-- end panel-scan card -->
  <div class="card" id="results" style="display:none">
    <div class="os-row" id="osInfo"></div>
    <div class="summary" id="summary"></div>
    <table id="table">
      <thead><tr>
        <th>Port</th><th>Stan</th><th>Usługa</th><th>Latencja</th><th>Banner</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
    <div class="export-row">
      <button class="btn-export" onclick="exportJSON()">Pobierz JSON</button>
      <button class="btn-export" onclick="exportCSV()">Pobierz CSV</button>
    </div>
  </div>
  </div> <!-- end panel-scan -->

  <!-- PANEL: odkryj sieć -->
  <div class="panel" id="panel-discover">
  <div class="card">
    <div class="row">
      <div>
        <label>Podsieć (pierwsze 3 oktety)</label>
        <input id="subnet" type="text" placeholder="192.168.1" value="192.168.1">
        <div class="hint">Przeskanuje 192.168.1.1 – 192.168.1.254</div>
      </div>
      <div>
        <label>Wątki</label>
        <input id="dthreads" type="number" value="100" min="1" max="500">
      </div>
    </div>
    <button id="discoverBtn" onclick="startDiscover()">Odkryj hosty</button>
    <div id="dstatus"></div>
  </div>
  <div class="card" id="discover-results" style="display:none">
    <div class="summary" id="dsummary"></div>
    <div id="host-list"></div>
  </div>
  </div> <!-- end panel-discover -->

</main>

<script>
let lastData = null;

async function startScan() {
  const host    = document.getElementById('host').value.trim();
  const ports   = document.getElementById('ports').value.trim();
  const timeout = document.getElementById('timeout').value;
  const threads = document.getElementById('threads').value;
  if (!host || !ports) return;

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  document.getElementById('status').textContent = 'Skanowanie...';
  document.getElementById('results').style.display = 'none';

  try {
    const r = await fetch(`/scan?host=${encodeURIComponent(host)}&ports=${encodeURIComponent(ports)}&timeout=${timeout}&threads=${threads}`);
    const data = await r.json();
    if (data.error) { document.getElementById('status').textContent = 'Błąd: ' + data.error; return; }
    lastData = data;
    renderResults(data);
    document.getElementById('status').textContent = '';
  } catch(e) {
    document.getElementById('status').textContent = 'Błąd połączenia: ' + e;
  } finally {
    btn.disabled = false;
  }
}

function renderResults(d) {
  const os = d.os_detection;
  document.getElementById('osInfo').innerHTML = `
    <div class="os-item"><label>Host</label><span>${d.host} (${d.ip})</span></div>
    <div class="os-item"><label>OS (szacowany)</label><span style="color:var(--yellow)">${os.os_guess}</span></div>
    ${os.ttl ? `<div class="os-item"><label>TTL</label><span>${os.ttl}</span></div>` : ''}
    <div class="os-item"><label>Skan o</label><span>${d.scanned_at.replace('T',' ').slice(0,19)}</span></div>
  `;

  const open   = d.ports.filter(p => p.open).length;
  const closed = d.ports.filter(p => !p.open).length;
  document.getElementById('summary').innerHTML = `
    <div class="stat"><span class="stat-val open-val">${open}</span><span class="stat-lbl">otwarte</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--red)">${closed}</span><span class="stat-lbl">zamknięte</span></div>
    <div class="stat"><span class="stat-val total-val">${open+closed}</span><span class="stat-lbl">razem</span></div>
  `;

  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  const sorted = [...d.ports].sort((a,b) => a.port - b.port);
  for (const p of sorted) {
    const tr = document.createElement('tr');
    const stateCell = p.open
      ? `<td><span class="badge badge-open">OPEN</span></td>`
      : `<td><span class="badge badge-closed">closed</span></td>`;
    const lat  = p.latency_ms != null ? p.latency_ms.toFixed(1) + ' ms' : '—';
    const ban  = p.banner ? `<span style="color:var(--muted);font-size:12px">${escHtml(p.banner)}</span>` : '';
    tr.innerHTML = `<td class="${p.open?'open':'closed'}">${p.port}</td>${stateCell}<td>${escHtml(p.service)}</td><td>${lat}</td><td>${ban}</td>`;
    tbody.appendChild(tr);
  }
  document.getElementById('results').style.display = 'block';
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function exportJSON() {
  if (!lastData) return;
  download('scan_results.json', JSON.stringify(lastData, null, 2), 'application/json');
}

function exportCSV() {
  if (!lastData) return;
  const rows = [['port','open','service','latency_ms','banner']];
  for (const p of lastData.ports.sort((a,b)=>a.port-b.port))
    rows.push([p.port, p.open, p.service, p.latency_ms??'', p.banner??'']);
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  download('scan_results.csv', csv, 'text/csv');
}

function download(name, content, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], {type}));
  a.download = name; a.click();
}

document.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', ['scan','discover'][i]===name));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
}

async function startDiscover() {
  const subnet  = document.getElementById('subnet').value.trim();
  const threads = document.getElementById('dthreads').value;
  if (!subnet) return;
  const btn = document.getElementById('discoverBtn');
  btn.disabled = true;
  document.getElementById('dstatus').textContent = 'Skanowanie sieci ' + subnet + '.0/24 — może potrwać 30–60 sekund...';
  document.getElementById('discover-results').style.display = 'none';
  try {
    const r = await fetch(`/discover?subnet=${encodeURIComponent(subnet)}&threads=${threads}`);
    const d = await r.json();
    if (d.error) { document.getElementById('dstatus').textContent = 'Błąd: ' + d.error; return; }
    renderDiscover(d);
    document.getElementById('dstatus').textContent = '';
  } catch(e) {
    document.getElementById('dstatus').textContent = 'Błąd: ' + e;
  } finally {
    btn.disabled = false;
  }
}

function renderDiscover(d) {
  document.getElementById('dsummary').innerHTML = `
    <div class="stat"><span class="stat-val open-val">${d.live_hosts.length}</span><span class="stat-lbl">aktywnych hostów</span></div>
    <div class="stat"><span class="stat-val" style="color:var(--muted)">254</span><span class="stat-lbl">sprawdzonych</span></div>
  `;
  const list = document.getElementById('host-list');
  if (!d.live_hosts.length) {
    list.innerHTML = '<div style="color:var(--muted);padding:16px">Nie znaleziono aktywnych hostów.</div>';
  } else {
    list.innerHTML = d.live_hosts.map(h => `
      <div class="host-row">
        <div>
          <span class="host-ip">${escHtml(h.ip)}</span>
          ${h.hostname ? `<span class="host-name">  ${escHtml(h.hostname)}</span>` : ''}
        </div>
        <button class="btn-scan-host" onclick="scanFromDiscover('${escHtml(h.ip)}')">Skanuj porty →</button>
      </div>`).join('');
  }
  document.getElementById('discover-results').style.display = 'block';
}

function scanFromDiscover(ip) {
  document.getElementById('host').value = ip;
  switchTab('scan');
  startScan();
}
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access log

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, "text/html", HTML.encode())
        elif parsed.path == "/discover":
            qs = parse_qs(parsed.query)
            subnet  = qs.get("subnet",  [""])[0].strip()
            threads = int(qs.get("threads", ["100"])[0])
            if not subnet or len(subnet.split(".")) != 3:
                self._json({"error": "podaj podsieć w formacie 192.168.1"})
                return
            try:
                live_ips = sc.discover_hosts(subnet, threads)
                hosts = []
                for ip in live_ips:
                    try:
                        name = __import__("socket").gethostbyaddr(ip)[0]
                    except Exception:
                        name = ""
                    hosts.append({"ip": ip, "hostname": name})
                self._json({"subnet": subnet + ".0/24",
                            "scanned_at": __import__("datetime").datetime.now().isoformat(),
                            "live_hosts": hosts})
            except Exception as e:
                self._json({"error": str(e)})
        elif parsed.path == "/scan":
            qs = parse_qs(parsed.query)
            host    = qs.get("host",    [""])[0].strip()
            ports   = qs.get("ports",   ["common"])[0].strip()
            timeout = float(qs.get("timeout", ["1.0"])[0])
            threads = int(qs.get("threads", ["100"])[0])
            if not host:
                self._json({"error": "missing host"})
                return
            try:
                ip, os_info, results = sc.run_scan(host, ports, timeout, threads, grab=True)
                payload = {
                    "host": host, "ip": ip,
                    "scanned_at": __import__("datetime").datetime.now().isoformat(),
                    "os_detection": os_info,
                    "ports": results,
                }
                self._json(payload)
            except SystemExit:
                self._json({"error": f"Cannot resolve {host!r}"})
            except Exception as e:
                self._json({"error": str(e)})
        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self._send(200, "application/json", body)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"\n  IP Scanner Pro — Web UI")
    print(f"  Otwórz: http://localhost:{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Zatrzymano.")


if __name__ == "__main__":
    main()
