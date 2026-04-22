"""
Plantilla de reporte HTML — KICS (Tema Corporativo: Simon)
Parsea la salida JSON de KICS v1.x / v2.x
Uso standalone: python3 kics_report.py <kics-results.json> <output.html>
En el pipeline: el script equivalente está inlineado en sec-containers.yml
"""
import json
import html
import os
import sys
import base64
from datetime import datetime, timezone

SEV_CSS = {
    "CRITICAL": "badge-critical",
    "HIGH":     "badge-high",
    "MEDIUM":   "badge-medium",
    "LOW":      "badge-low",
    "INFO":     "badge-info",
}


def get_base64_image(image_path):
    try:
        if os.path.exists(image_path):
            with open(image_path, "rb") as img_file:
                ext = image_path.split('.')[-1].lower()
                mime = "image/svg+xml" if ext == "svg" else f"image/{ext}"
                encoded = base64.b64encode(img_file.read()).decode('utf-8')
                return f"data:{mime};base64,{encoded}"
        return ""
    except Exception:
        return ""


def _build_rows(queries: list) -> str:
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
            files_html += f'<div style="color:#888888;font-size:11px">+{len(files)-5} más...</div>'
        rows += (
            f"<tr>"
            f'<td><span class="badge {css}">{sev}</span></td>'
            f"<td><strong>{qname}</strong><br>"
            f'<span style="font-size:11px;color:#00F1C7">{category}</span></td>'
            f'<td><span style="font-size:12px;color:#888888">{platform}</span></td>'
            f"<td>{files_html}</td>"
            f'<td style="font-size:12px;color:#B0B0B0">{desc}</td>'
            f"</tr>\n"
        )
    return rows


def generate(data: dict, repo_name: str, repo_full: str, sha: str, ref: str) -> str:
    fecha    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    queries  = data.get("queries", [])
    counters = data.get("severity_counters", {})
    total    = data.get("total_counter", 0)

    base_dir  = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(base_dir, "..", "image", "logo_claro.png")
    logo_b64  = get_base64_image(logo_path)
    logo_html = (f'<img src="{logo_b64}" alt="Simon" height="45">'
                 if logo_b64 else '<h2 style="color:#00F1C7;margin-bottom:10px;">Simon</h2>')

    rows = _build_rows(queries)

    no_findings = (
        ""
        if total > 0
        else """<div class="no-findings">
          <div class="no-findings-icon" style="color:#4EDA56;">✅</div>
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
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#1A1A1A;color:#E7E7E7}}

    .header{{background:#000000;border-bottom:2px solid #00F1C7;padding:30px 40px;position:relative}}
    .logo-container{{margin-bottom:15px}}
    .tool-badge{{background:rgba(0,241,199,0.1);border:1px solid #00F1C7;color:#00F1C7;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:700}}
    .header h1{{font-size:26px;font-weight:700;color:#FFFFFF;margin-top:16px}}
    .meta{{color:#B0B0B0;font-size:13px;margin-top:10px}}
    .meta span{{margin-right:20px}}

    .btn-pdf{{position:absolute;top:40px;right:40px;background:#00F1C7;color:#000000;font-weight:bold;padding:10px 20px;border:none;border-radius:6px;cursor:pointer;font-size:14px;transition:0.2s}}
    .btn-pdf:hover{{background:#00c4a0}}

    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:16px;padding:30px;max-width:1100px;margin:0 auto}}
    .card{{background:#373737;border-radius:8px;padding:20px;text-align:center;border-top:4px solid}}
    .card-total{{border-top-color:#B0B0B0}}
    .card-critical{{border-top-color:#F63D3D}}
    .card-high{{border-top-color:#FAD900}}
    .card-medium{{border-top-color:#00F1C7}}
    .card-low{{border-top-color:#888888}}
    .card-info{{border-top-color:#4b8aba}}
    .card-num{{font-size:34px;font-weight:800;line-height:1}}
    .card-label{{font-size:11px;color:#B0B0B0;text-transform:uppercase;margin-top:8px;letter-spacing:1px}}
    .num-total{{color:#FFFFFF}} .num-crit{{color:#F63D3D}} .num-high{{color:#FAD900}}
    .num-med{{color:#00F1C7}} .num-low{{color:#888888}} .num-info{{color:#4b8aba}}

    .section{{max-width:1100px;margin:0 auto 30px;padding:0 30px}}
    .section-title{{font-size:16px;font-weight:600;color:#00F1C7;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #373737}}
    .wrap{{background:#000000;border:1px solid #373737;border-radius:8px;overflow:hidden}}
    table{{width:100%;border-collapse:collapse}}
    thead{{background:#373737}}
    th{{padding:14px 16px;color:#E7E7E7;font-size:12px;text-transform:uppercase;text-align:left;letter-spacing:0.5px}}
    td{{padding:14px 16px;border-bottom:1px solid #373737;font-size:13px;vertical-align:top;color:#D1D1D1}}
    tr:hover td{{background:#1A1A1A}}

    .badge{{display:inline-block;padding:4px 12px;border-radius:12px;font-size:11px;font-weight:bold;text-transform:uppercase}}
    .badge-critical{{background:rgba(246,61,61,0.15);color:#F63D3D;border:1px solid #F63D3D}}
    .badge-high{{background:rgba(250,217,0,0.15);color:#FAD900;border:1px solid #FAD900}}
    .badge-medium{{background:rgba(0,241,199,0.15);color:#00F1C7;border:1px solid #00F1C7}}
    .badge-low{{background:rgba(136,136,136,0.15);color:#888888;border:1px solid #888888}}
    .badge-info{{background:rgba(75,138,186,0.15);color:#4b8aba;border:1px solid #4b8aba}}

    .file-path{{color:#888888;font-family:monospace;font-size:11px;margin-top:2px}}

    .no-findings{{text-align:center;padding:80px 40px}}
    .no-findings-icon{{font-size:60px;margin-bottom:16px}}
    .no-findings h3{{font-size:20px;color:#4EDA56;margin-bottom:8px}}
    .no-findings p{{color:#B0B0B0}}
    .footer{{text-align:center;padding:30px;color:#888888;font-size:12px;border-top:1px solid #373737;margin-top:20px}}

    @media print {{
      body{{background:#FFFFFF !important;color:#000000 !important}}
      .header{{background:#FFFFFF !important;border-bottom:2px solid #00F1C7 !important;padding:20px 0}}
      .header h1{{color:#000000 !important}}
      .btn-pdf{{display:none !important}}
      .wrap{{border:1px solid #D1D1D1 !important;background:#FFFFFF !important}}
      thead{{background:#F6F6F6 !important}}
      th{{color:#373737 !important}}
      td{{border-bottom:1px solid #E7E7E7 !important;color:#1A1A1A !important}}
      .card{{background:#F6F6F6 !important;border:1px solid #E7E7E7 !important;border-top:4px solid !important}}
    }}
  </style>
</head>
<body>
  <div class="header">
    <button class="btn-pdf" onclick="window.print()">📥 Descargar PDF</button>
    <div class="logo-container">{logo_html}</div>
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

  <div class="footer">Generado por <strong>pipelines-centrales</strong> · Equipo Cybersecurity · Simon · {fecha}</div>
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
