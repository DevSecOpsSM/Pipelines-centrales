"""
Plantilla de reporte HTML — Hadolint (Dockerfile linter)
Parsea la salida JSON de Hadolint: array de objetos {code, message, level, line, column, file}
Uso standalone: python3 hadolint_report.py <hadolint-raw.json> <output.html>
En el pipeline: el script equivalente está inlineado en sec-containers.yml
"""
import json
import html
import os
import sys
from datetime import datetime

SEV_CSS = {
    "error":   "badge-critical",
    "warning": "badge-high",
    "info":    "badge-medium",
    "style":   "badge-low",
}


def generate(findings: list, repo_name: str, repo_full: str, sha: str, ref: str) -> str:
    fecha  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    counts = {"error": 0, "warning": 0, "info": 0, "style": 0}
    for f in findings:
        lv = f.get("level", "info").lower()
        counts[lv] = counts.get(lv, 0) + 1
    total = len(findings)

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
            f'style="color:#58a6ff;text-decoration:none" target="_blank">{code}</a></td>'
            f'<td class="file-path">{loc}</td>'
            f"<td>{msg}</td>"
            f"</tr>\n"
        )

    no_findings = (
        ""
        if total > 0
        else """<div class="no-findings">
          <div class="no-findings-icon">✅</div>
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
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9}}
    .header{{background:linear-gradient(135deg,#0d1117,#161b22,#1c2128);border-bottom:1px solid #30363d;padding:40px}}
    .tool-badge{{background:#0d2d1e;border:1px solid #238636;color:#3fb950;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:700}}
    .header h1{{font-size:26px;font-weight:700;color:#f0f6fc;margin-top:12px}}
    .meta{{color:#8b949e;font-size:13px;margin-top:8px}}
    .meta span{{margin-right:20px}}
    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;padding:30px;max-width:1100px;margin:0 auto}}
    .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;text-align:center;border-top:3px solid}}
    .card-total{{border-top-color:#8b949e}} .card-error{{border-top-color:#da3633}}
    .card-warning{{border-top-color:#9e6a03}} .card-info{{border-top-color:#1f6feb}} .card-style{{border-top-color:#3d444d}}
    .card-num{{font-size:36px;font-weight:800;line-height:1}}
    .card-label{{font-size:11px;color:#8b949e;text-transform:uppercase;margin-top:6px}}
    .num-total{{color:#c9d1d9}} .num-error{{color:#f85149}} .num-warn{{color:#d29922}}
    .num-info{{color:#58a6ff}} .num-style{{color:#7d8590}}
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
    .file-path{{color:#7d8590;font-family:monospace;font-size:12px}}
    .no-findings{{text-align:center;padding:80px 40px}}
    .no-findings-icon{{font-size:60px;margin-bottom:16px}}
    .no-findings h3{{font-size:20px;color:#3fb950;margin-bottom:8px}}
    .no-findings p{{color:#8b949e}}
    .footer{{text-align:center;padding:30px;color:#8b949e;font-size:12px;border-top:1px solid #21262d}}
  </style>
</head>
<body>
  <div class="header">
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
  <div class="footer">Generado por <strong>pipelines-centrales</strong> · Equipo Cybersecurity · {fecha}</div>
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
