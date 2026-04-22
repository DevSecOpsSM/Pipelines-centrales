"""
Plantilla de reporte HTML — TruffleHog
Parsea NDJSON (un objeto JSON por línea) — formato nativo de TruffleHog v3
Uso standalone: python3 trufflehog_report.py <trufflehog-raw.json> <output.html>
En el pipeline: el script equivalente está inlineado en sec-secrets.yml
"""
import json
import html
import os
import sys
from datetime import datetime


def generate(findings: list, repo_name: str, repo_full: str, sha: str, ref: str) -> str:
    fecha    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    count    = len(findings)
    verified = sum(1 for f in findings if f.get("Verified", False))

    rows = ""
    for f in findings:
        detector  = html.escape(str(f.get("DetectorName", "N/A")))
        is_verf   = f.get("Verified", False)
        badge_cls = "badge-critical" if is_verf else "badge-medium"
        badge_txt = "VERIFICADO" if is_verf else "NO VERIFICADO"
        raw       = str(f.get("Raw", ""))
        redac     = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else "****"
        meta      = f.get("SourceMetadata", {}).get("Data", {})
        file_info = ""
        for key in ("Git", "Filesystem", "S3", "Github", "Gitlab"):
            if key in meta:
                d = meta[key]
                file_info = html.escape(str(d.get("file", d.get("key", d.get("repository", "?")))))
                break
        rows += (
            f"<tr>"
            f'<td><span class="badge {badge_cls}">{badge_txt}</span></td>'
            f"<td><strong>{detector}</strong></td>"
            f'<td class="file-path">{file_info or "N/A"}</td>'
            f"<td><code>{html.escape(redac)}</code></td>"
            f"</tr>\n"
        )

    no_findings = (
        ""
        if count > 0
        else """<div class="no-findings">
          <div class="no-findings-icon">✅</div>
          <h3>Sin secretos detectados</h3>
          <p>TruffleHog no encontró credenciales expuestas en el repositorio.</p>
        </div>"""
    )
    table = (
        f"""<table>
          <thead><tr>
            <th>Estado</th><th>Detector</th><th>Archivo/Fuente</th><th>Secret (redactado)</th>
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
  <title>TruffleHog Report — {repo_name}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9}}
    .header{{background:linear-gradient(135deg,#0d1117,#161b22,#1c2128);border-bottom:1px solid #30363d;padding:40px}}
    .tool-badge{{background:#3d2e08;border:1px solid #9e6a03;color:#d29922;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:700}}
    .header h1{{font-size:26px;font-weight:700;color:#f0f6fc;margin-top:12px}}
    .meta{{color:#8b949e;font-size:13px;margin-top:8px}}
    .meta span{{margin-right:20px}}
    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;padding:30px;max-width:1100px;margin:0 auto}}
    .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;text-align:center;border-top:3px solid}}
    .card-total{{border-top-color:#8b949e}} .card-verified{{border-top-color:#da3633}} .card-unverified{{border-top-color:#9e6a03}}
    .card-num{{font-size:40px;font-weight:800;line-height:1}}
    .card-label{{font-size:11px;color:#8b949e;text-transform:uppercase;margin-top:6px}}
    .num-total{{color:#c9d1d9}} .num-crit{{color:#f85149}} .num-warn{{color:#d29922}}
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
    .badge-medium{{background:#3d2e08;color:#d29922;border:1px solid #9e6a03}}
    code{{background:#21262d;color:#d29922;padding:2px 6px;border-radius:4px;font-size:12px}}
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
    <span class="tool-badge">TRUFFLEHOG</span>
    <h1>Verified Secrets Detection Report</h1>
    <div class="meta">
      <span>📦 {html.escape(repo_full)}</span>
      <span>🌿 {html.escape(ref)}</span>
      <span>🔖 {sha[:7]}</span>
      <span>🕐 {fecha}</span>
    </div>
  </div>
  <div class="cards">
    <div class="card card-total"><div class="card-num num-total">{count}</div><div class="card-label">Total</div></div>
    <div class="card card-verified"><div class="card-num num-crit">{verified}</div><div class="card-label">Verificados (activos)</div></div>
    <div class="card card-unverified"><div class="card-num num-warn">{count - verified}</div><div class="card-label">Sin verificar</div></div>
  </div>
  <div class="section">
    <div class="section-title">Hallazgos — TruffleHog</div>
    <div class="wrap">{table}{no_findings}</div>
  </div>
  <div class="footer">Generado por <strong>pipelines-centrales</strong> · Equipo Cybersecurity · {fecha}</div>
</body>
</html>"""


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 trufflehog_report.py <trufflehog-raw.json> <output.html>")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]
    repo_name   = os.environ.get("REPO_NAME", "unknown")
    repo_full   = os.environ.get("REPO_FULL", repo_name)
    sha         = os.environ.get("SHA", "000000")
    ref         = os.environ.get("REF", "main")

    findings = []
    if os.path.exists(input_path):
        for line in open(input_path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except Exception:
                pass

    content = generate(findings, repo_name, repo_full, sha, ref)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"[TruffleHog] {len(findings)} hallazgo(s) → {output_path}")


if __name__ == "__main__":
    main()
