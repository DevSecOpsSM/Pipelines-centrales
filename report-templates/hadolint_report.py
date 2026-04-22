"""
Plantilla de reporte HTML — Hadolint (Tema Corporativo: Simon)
Parsea la salida JSON de Hadolint: array de objetos {code, message, level, line, column, file}
Uso standalone: python3 hadolint_report.py <hadolint-raw.json> <output.html>
En el pipeline: el script equivalente está inlineado en sec-containers.yml
"""
import json
import html
import os
import sys
import base64
from datetime import datetime, timezone

SEV_CSS = {
    "error":   "badge-critical",
    "warning": "badge-high",
    "info":    "badge-medium",
    "style":   "badge-low",
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


def _build_rows(findings: list) -> str:
    rows = ""
    for f in findings:
        level    = f.get("level", "info").lower()
        css      = SEV_CSS.get(level, "badge-low")
        code     = html.escape(str(f.get("code", "?")))
        msg      = html.escape(str(f.get("message", ""))[:200])
        file_raw = str(f.get("file", "?"))
        file_esc = html.escape(file_raw.lstrip("./"))
        line     = f.get("line", "?")
        col      = f.get("column", "")
        loc      = f"{file_esc}:{line}" + (f":{col}" if col else "")
        rows += (
            f"<tr>"
            f'<td><span class="badge {css}">{level.upper()}</span></td>'
            f'<td><a href="https://github.com/hadolint/hadolint/wiki/{code}" '
            f'style="color:#00F1C7;text-decoration:none" target="_blank">{code}</a></td>'
            f'<td class="file-path">{loc}</td>'
            f"<td>{msg}</td>"
            f"</tr>\n"
        )
    return rows


def generate(findings: list, repo_name: str, repo_full: str, sha: str, ref: str) -> str:
    fecha  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {"error": 0, "warning": 0, "info": 0, "style": 0}
    for f in findings:
        lv = f.get("level", "info").lower()
        counts[lv] = counts.get(lv, 0) + 1
    total = len(findings)

    base_dir  = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(base_dir, "..", "image", "logo_claro.png")
    logo_b64  = get_base64_image(logo_path)
    logo_html = (f'<img src="{logo_b64}" alt="Simon" height="45">'
                 if logo_b64 else '<h2 style="color:#00F1C7;margin-bottom:10px;">Simon</h2>')

    rows = _build_rows(findings)

    no_findings = (
        ""
        if total > 0
        else """<div class="no-findings">
          <div class="no-findings-icon" style="color:#4EDA56;">✅</div>
          <h3>Sin problemas en Dockerfiles</h3>
          <p>Hadolint no encontró violaciones, o no hay Dockerfiles en el repositorio.</p>
        </div>"""
    )
    table = (
        f"""<table>
          <thead><tr>
            <th>Nivel</th><th>Código</th><th>Archivo:Línea</th><th>Descripción</th>
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
  <title>Hadolint Report — {repo_name}</title>
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

    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;padding:30px;max-width:1100px;margin:0 auto}}
    .card{{background:#373737;border-radius:8px;padding:20px;text-align:center;border-top:4px solid}}
    .card-total{{border-top-color:#B0B0B0}}
    .card-error{{border-top-color:#F63D3D}}
    .card-warning{{border-top-color:#FAD900}}
    .card-info{{border-top-color:#00F1C7}}
    .card-style{{border-top-color:#888888}}
    .card-num{{font-size:36px;font-weight:800;line-height:1}}
    .card-label{{font-size:11px;color:#B0B0B0;text-transform:uppercase;margin-top:8px;letter-spacing:1px}}
    .num-total{{color:#FFFFFF}} .num-error{{color:#F63D3D}} .num-warn{{color:#FAD900}}
    .num-info{{color:#00F1C7}} .num-style{{color:#888888}}

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

    .file-path{{color:#888888;font-family:monospace;font-size:12px}}

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
    <span class="tool-badge">HADOLINT — DOCKERFILE LINTER</span>
    <h1>Dockerfile Best Practices Report</h1>
    <div class="meta">
      <span>📦 {html.escape(repo_full)}</span>
      <span>🌿 {html.escape(ref)}</span>
      <span>🔖 {sha[:7]}</span>
      <span>🕐 {fecha}</span>
    </div>
  </div>

  <div class="cards">
    <div class="card card-total"><div class="card-num num-total">{total}</div><div class="card-label">Total</div></div>
    <div class="card card-error"><div class="card-num num-error">{counts.get("error",0)}</div><div class="card-label">Error</div></div>
    <div class="card card-warning"><div class="card-num num-warn">{counts.get("warning",0)}</div><div class="card-label">Warning</div></div>
    <div class="card card-info"><div class="card-num num-info">{counts.get("info",0)}</div><div class="card-label">Info</div></div>
    <div class="card card-style"><div class="card-num num-style">{counts.get("style",0)}</div><div class="card-label">Style</div></div>
  </div>

  <div class="section">
    <div class="section-title">Hallazgos — Hadolint Dockerfile Linter</div>
    <div class="wrap">{table}{no_findings}</div>
  </div>

  <div class="footer">Generado por <strong>pipelines-centrales</strong> · Equipo Cybersecurity · Simon · {fecha}</div>
</body>
</html>"""


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 hadolint_report.py <hadolint-raw.json> <output.html>")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]
    repo_name   = os.environ.get("REPO_NAME", "unknown")
    repo_full   = os.environ.get("REPO_FULL", repo_name)
    sha         = os.environ.get("SHA", "000000")
    ref         = os.environ.get("REF", "main")

    findings = []
    if os.path.exists(input_path):
        try:
            findings = json.load(open(input_path, encoding="utf-8"))
            if not isinstance(findings, list):
                findings = []
        except Exception as e:
            print(f"[WARN] Error leyendo {input_path}: {e}", file=sys.stderr)

    content = generate(findings, repo_name, repo_full, sha, ref)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"[Hadolint] {len(findings)} hallazgo(s) → {output_path}")


if __name__ == "__main__":
    main()
