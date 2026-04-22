"""
Plantilla de reporte HTML — Gitleaks
Uso standalone (referencia): python3 gitleaks_report.py <input.json> <output.html>
En el pipeline: el script equivalente está inlineado en sec-secrets.yml
"""
import json
import html
import os
import sys
from datetime import datetime


def generate(findings: list, repo_name: str, repo_full: str, sha: str, ref: str) -> str:
    fecha = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    count = len(findings)

    rows = ""
    for f in findings:
        rule  = html.escape(str(f.get("RuleID", "N/A")))
        desc  = html.escape(str(f.get("Description", "N/A")))
        file  = html.escape(str(f.get("File", "N/A")))
        line  = f.get("StartLine", "?")
        raw   = str(f.get("Match", ""))
        redac = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else "****"
        rows += (
            f"<tr>"
            f'<td><span class="badge badge-critical">SECRET</span></td>'
            f"<td><code>{rule}</code></td>"
            f'<td class="file-path">{file}:{line}</td>'
            f"<td>{desc}</td>"
            f"<td><code>{html.escape(redac)}</code></td>"
            f"</tr>\n"
        )

    no_findings = (
        ""
        if count > 0
        else """<div class="no-findings">
          <div class="no-findings-icon">✅</div>
          <h3>Sin secretos detectados</h3>
          <p>Gitleaks analizó el historial completo sin encontrar secretos expuestos.</p>
        </div>"""
    )
    table = (
        f"""<table>
          <thead><tr>
            <th>Tipo</th><th>Regla</th><th>Archivo:Línea</th>
            <th>Descripción</th><th>Match (redactado)</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
        if count > 0
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Gitleaks Report — {repo_name}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9}}
    .header{{background:linear-gradient(135deg,#0d1117,#161b22,#1c2128);border-bottom:1px solid #30363d;padding:40px}}
    .tool-badge{{background:#3d1114;border:1px solid #da3633;color:#f85149;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:700}}
    .header h1{{font-size:26px;font-weight:700;color:#f0f6fc;margin-top:12px}}
    .meta{{color:#8b949e;font-size:13px;margin-top:8px}}
    .meta span{{margin-right:20px}}
    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;padding:30px;max-width:1100px;margin:0 auto}}
    .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;text-align:center;border-top:3px solid #da3633}}
    .card-num{{font-size:40px;font-weight:800;color:#f85149}}
    .card-label{{font-size:12px;color:#8b949e;text-transform:uppercase;margin-top:6px}}
    .section{{max-width:1100px;margin:0 auto 30px;padding:0 30px}}
    .section-title{{font-size:16px;font-weight:600;color:#58a6ff;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #21262d}}
    .wrap{{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}}
    table{{width:100%;border-collapse:collapse}}
    thead{{background:#21262d}}
    th{{padding:12px 16px;color:#8b949e;font-size:12px;text-transform:uppercase;text-align:left}}
    td{{padding:12px 16px;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top}}
    tr:hover td{{background:#1c2128}}
    .badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase}}
    .badge-critical{{background:#3d1114;color:#f85149;border:1px solid #da3633}}
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
    <span class="tool-badge">GITLEAKS</span>
    <h1>Secrets Detection Report</h1>
    <div class="meta">
      <span>📦 {html.escape(repo_full)}</span>
      <span>🌿 {html.escape(ref)}</span>
      <span>🔖 {sha[:7]}</span>
      <span>🕐 {fecha}</span>
    </div>
  </div>
  <div class="cards">
    <div class="card">
      <div class="card-num">{count}</div>
      <div class="card-label">Secretos detectados</div>
    </div>
  </div>
  <div class="section">
    <div class="section-title">Hallazgos</div>
    <div class="wrap">{table}{no_findings}</div>
  </div>
  <div class="footer">Generado por <strong>pipelines-centrales</strong> · Equipo Cybersecurity · {fecha}</div>
</body>
</html>"""


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 gitleaks_report.py <input.json> <output.html>")
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
            data = json.load(open(input_path, encoding="utf-8"))
            if isinstance(data, list):
                findings = data
        except Exception as e:
            print(f"[WARN] Error leyendo {input_path}: {e}", file=sys.stderr)

    content = generate(findings, repo_name, repo_full, sha, ref)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"[Gitleaks] {len(findings)} secreto(s) → {output_path}")


if __name__ == "__main__":
    main()
