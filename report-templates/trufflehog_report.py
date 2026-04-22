"""
Plantilla de reporte HTML — TruffleHog (Tema Corporativo: Simon)
Parsea NDJSON (un objeto JSON por línea) — formato nativo de TruffleHog v3
Uso standalone: python3 trufflehog_report.py <trufflehog-raw.json> <output.html>
En el pipeline: el script equivalente está inlineado en sec-secrets.yml
"""
import json
import html
import os
import sys
import base64
from datetime import datetime, timezone


def get_base64_image(image_path):
    try:
        if os.path.exists(image_path):
            with open(image_path, "rb") as img_file:
                ext = image_path.split('.')[-1].lower()
                mime = f"image/{ext}"
                if ext == "svg": mime = "image/svg+xml"
                encoded = base64.b64encode(img_file.read()).decode('utf-8')
                return f"data:{mime};base64,{encoded}"
        return ""
    except Exception:
        return ""


def _file_from_meta(meta: dict) -> str:
    for key in ("Git", "Filesystem", "S3", "Github", "Gitlab"):
        if key in meta:
            d = meta[key]
            return html.escape(str(d.get("file", d.get("key", d.get("repository", "?")))))
    return "N/A"


def _build_rows(findings: list) -> str:
    rows = ""
    for f in findings:
        detector  = html.escape(str(f.get("DetectorName", "N/A")))
        is_verf   = f.get("Verified", False)
        badge_cls = "badge-critical" if is_verf else "badge-high"
        badge_txt = "VERIFICADO" if is_verf else "NO VERIFICADO"
        raw       = str(f.get("Raw", ""))
        redac     = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else "****"
        file_info = _file_from_meta(f.get("SourceMetadata", {}).get("Data", {}))
        rows += (
            f"<tr>"
            f'<td><span class="badge {badge_cls}">{badge_txt}</span></td>'
            f"<td><strong>{detector}</strong></td>"
            f'<td class="file-path">{file_info}</td>'
            f"<td><code>{html.escape(redac)}</code></td>"
            f"</tr>\n"
        )
    return rows


def generate(findings: list, repo_name: str, repo_full: str, sha: str, ref: str) -> str:
    fecha    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    count    = len(findings)
    verified = sum(1 for f in findings if f.get("Verified", False))

    base_dir  = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(base_dir, "..", "image", "logo_claro.png")
    logo_b64  = get_base64_image(logo_path)
    logo_html = (f'<img src="{logo_b64}" alt="Simon" height="45">'
                 if logo_b64 else '<h2 style="color:#00F1C7;margin-bottom:10px;">Simon</h2>')

    rows = _build_rows(findings)

    no_findings = (
        ""
        if count > 0
        else """<div class="no-findings">
          <div class="no-findings-icon" style="color:#4EDA56;">✅</div>
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
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#1A1A1A;color:#E7E7E7}}

    .header{{background:#000000;border-bottom:2px solid #00F1C7;padding:30px 40px;position:relative}}
    .logo-container{{margin-bottom:15px}}
    .tool-badge{{background:rgba(0,241,199,0.1);border:1px solid #00F1C7;color:#00F1C7;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:700}}
    .header h1{{font-size:26px;font-weight:700;color:#FFFFFF;margin-top:16px}}
    .meta{{color:#B0B0B0;font-size:13px;margin-top:10px}}
    .meta span{{margin-right:20px}}

    .btn-pdf{{position:absolute;top:40px;right:40px;background:#00F1C7;color:#000000;font-weight:bold;padding:10px 20px;border:none;border-radius:6px;cursor:pointer;font-size:14px;transition:0.2s}}
    .btn-pdf:hover{{background:#00c4a0}}

    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;padding:30px;max-width:1100px;margin:0 auto}}
    .card{{background:#373737;border-radius:8px;padding:20px;text-align:center;border-top:4px solid}}
    .card-total{{border-top-color:#B0B0B0}}
    .card-verified{{border-top-color:#F63D3D}}
    .card-unverified{{border-top-color:#FAD900}}
    .card-num{{font-size:40px;font-weight:800;line-height:1}}
    .card-label{{font-size:11px;color:#B0B0B0;text-transform:uppercase;margin-top:8px;letter-spacing:1px}}
    .num-total{{color:#FFFFFF}} .num-crit{{color:#F63D3D}} .num-warn{{color:#FAD900}}

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

    code{{background:#373737;color:#00F1C7;padding:3px 6px;border-radius:4px;font-size:11.5px;word-break:break-all}}
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
      code{{background:#F6F6F6 !important;color:#006257 !important}}
    }}
  </style>
</head>
<body>
  <div class="header">
    <button class="btn-pdf" onclick="window.print()">📥 Descargar PDF</button>
    <div class="logo-container">{logo_html}</div>
    <span class="tool-badge">TRUFFLEHOG — SECRETS SCAN</span>
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

  <div class="footer">Generado por <strong>pipelines-centrales</strong> · Equipo Cybersecurity · Simon · {fecha}</div>
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
