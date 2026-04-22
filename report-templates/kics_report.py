"""
Plantilla de reporte HTML — KICS (Keeping Infrastructure as Code Secure)
Parsea la salida JSON de KICS v1.x / v2.x
Uso standalone: python3 kics_report.py <kics-results.json> <output.html>
En el pipeline: el script equivalente está inlineado en sec-containers.yml
"""
import json
import html
import os
import sys
from datetime import datetime

SEV_CSS = {
    "CRITICAL": "badge-critical",
    "HIGH": "badge-high",
    "MEDIUM": "badge-medium",
    "LOW": "badge-low",
    "INFO": "badge-info",
}


def generate(data: dict, repo_name: str, repo_full: str, sha: str, ref: str) -> str:
    fecha    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    queries  = data.get("queries", [])
    counters = data.get("severity_counters", {})
    total    = data.get("total_counter", 0)

    rows = ""
    for q in queries:
        sev      = q.get("severity", "INFO").upper()
        css      = SEV_CSS.get(sev, "badge-info")
        qname    = html.escape(q.get("query_name", "N/A"))
        category = html.escape(q.get("category", "N/A"))
        platform = html.escape(q.get("platform", "N/A"))
        desc     = html.escape(q.get("description", "")[:200])
        files    = q.get("files", [])
        files_html = "".join(
            f'<div class="file-path">{html.escape(str(f.get("file_name","?")))}'
            f':{f.get("line","?")}</div>'
            for f in files[:5]
        )
        if len(files) > 5:
            files_html += f'<div style="color:#8b949e;font-size:11px">+{len(files)-5} más...</div>'
        rows += (
            f"<tr>"
            f'<td><span class="badge {css}">{sev}</span></td>'
            f"<td><strong>{qname}</strong><br>"
            f'<span style="font-size:11px;color:#58a6ff">{category}</span></td>'
            f'<td><span style="font-size:12px;color:#8b949e">{platform}</span></td>'
            f"<td>{files_html}</td>"
            f'<td style="font-size:12px;color:#8b949e">{desc}</td>'
            f"</tr>\n"
        )

    no_findings = (
        ""
        if total > 0
        else """<div class="no-findings">
          <div class="no-findings-icon">✅</div>
          <h3>Sin hallazgos de seguridad IaC</h3>
          <p>KICS no detectó misconfiguraciones en los archivos de infraestructura.</p>
        </div>"""
    )
    table = (
        f"""<table>
          <thead><tr>
            <th>Severidad</th><th>Vulnerabilidad</th><th>Plataforma</th>
            <th>Archivos afectados</th><th>Descripción</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
        if total > 0
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>KICS IaC Report — {repo_name}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9}}
    .header{{background:linear-gradient(135deg,#0d1117,#161b22,#1c2128);border-bottom:1px solid #30363d;padding:40px}}
    .tool-badge{{background:#2d1e0a;border:1px solid #d29922;color:#d29922;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:700}}
    .header h1{{font-size:26px;font-weight:700;color:#f0f6fc;margin-top:12px}}
    .meta{{color:#8b949e;font-size:13px;margin-top:8px}}
    .meta span{{margin-right:20px}}
    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:16px;padding:30px;max-width:1100px;margin:0 auto}}
    .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;text-align:center;border-top:3px solid}}
    .card-total{{border-top-color:#8b949e}} .card-critical{{border-top-color:#da3633}}
    .card-high{{border-top-color:#9e6a03}} .card-medium{{border-top-color:#1f6feb}}
    .card-low{{border-top-color:#3d444d}} .card-info{{border-top-color:#1f4f8f}}
    .card-num{{font-size:34px;font-weight:800;line-height:1}}
    .card-label{{font-size:11px;color:#8b949e;text-transform:uppercase;margin-top:6px}}
    .num-total{{color:#c9d1d9}} .num-crit{{color:#f85149}} .num-high{{color:#d29922}}
    .num-med{{color:#58a6ff}} .num-low{{color:#7d8590}} .num-info{{color:#4b8aba}}
    .section{{max-width:1100px;margin:0 auto 30px;padding:0 30px}}
    .section-title{{font-size:16px;font-weight:600;color:#58a6ff;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #21262d}}
    .wrap{{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}}
    table{{width:100%;border-collapse:collapse}}
    thead{{background:#21262d}}
    th{{padding:12px 16px;color:#8b949e;font-size:12px;text-transform:uppercase;text-align:left}}
    td{{padding:11px 16px;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top}}
    tr:hover td{{background:#1c2128}}
    .badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase}}
    .badge-critical{{background:#3d1114;color:#f85149;border:1px solid #da3633}}
    .badge-high{{background:#3d2e08;color:#d29922;border:1px solid #9e6a03}}
    .badge-medium{{background:#0d1d31;color:#58a6ff;border:1px solid #1f6feb}}
    .badge-low{{background:#1c2128;color:#7d8590;border:1px solid #3d444d}}
    .badge-info{{background:#0d1a2d;color:#4b8aba;border:1px solid #1f4f8f}}
    .file-path{{color:#7d8590;font-family:monospace;font-size:11px;margin-top:2px}}
    .no-findings{{text-align:center;padding:80px 40px}}
    .no-findings-icon{{font-size:60px;margin-bottom:16px}}
    .no-findings h3{{font-size:20px;color:#3fb950;margin-bottom:8px}}
    .no-findings p{{color:#8b949e}}
    .footer{{text-align:center;padding:30px;color:#8b949e;font-size:12px;border-top:1px solid #21262d}}
  </style>
</head>
<body>
  <div class="header">
    <span class="tool-badge">KICS — IaC SECURITY</span>
    <h1>Infrastructure as Code Security Report</h1>
    <div class="meta">
      <span>📦 {html.escape(repo_full)}</span>
      <span>🌿 {html.escape(ref)}</span>
      <span>🔖 {sha[:7]}</span>
      <span>🕐 {fecha}</span>
    </div>
  </div>
  <div class="cards">
    <div class="card card-total"><div class="card-num num-total">{total}</div><div class="card-label">Total</div></div>
    <div class="card card-critical"><div class="card-num num-crit">{counters.get("CRITICAL",0)}</div><div class="card-label">Critical</div></div>
    <div class="card card-high"><div class="card-num num-high">{counters.get("HIGH",0)}</div><div class="card-label">High</div></div>
    <div class="card card-medium"><div class="card-num num-med">{counters.get("MEDIUM",0)}</div><div class="card-label">Medium</div></div>
    <div class="card card-low"><div class="card-num num-low">{counters.get("LOW",0)}</div><div class="card-label">Low</div></div>
    <div class="card card-info"><div class="card-num num-info">{counters.get("INFO",0)}</div><div class="card-label">Info</div></div>
  </div>
  <div class="section">
    <div class="section-title">Hallazgos — KICS (Dockerfiles · K8s · Terraform · Ansible · Helm)</div>
    <div class="wrap">{table}{no_findings}</div>
  </div>
  <div class="footer">Generado por <strong>pipelines-centrales</strong> · Equipo Cybersecurity · {fecha}</div>
</body>
</html>"""


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 kics_report.py <kics-results.json> <output.html>")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]
    repo_name   = os.environ.get("REPO_NAME", "unknown")
    repo_full   = os.environ.get("REPO_FULL", repo_name)
    sha         = os.environ.get("SHA", "000000")
    ref         = os.environ.get("REF", "main")

    data = {}
    if os.path.exists(input_path):
        try:
            data = json.load(open(input_path, encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] Error leyendo {input_path}: {e}", file=sys.stderr)

    content = generate(data, repo_name, repo_full, sha, ref)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    total = data.get("total_counter", 0)
    print(f"[KICS] {total} hallazgo(s) → {output_path}")


if __name__ == "__main__":
    main()
