Contexto:
Actúa como un Arquitecto DevSecOps Senior experto en GitHub Actions. Estoy construyendo una arquitectura de CI/CD centralizada para mi organización utilizando Workflows Reutilizables (Reusable Workflows) con el disparador on: workflow_call.

El objetivo es crear un repositorio central llamado pipelines-centrales que contenga plantillas de seguridad individuales, cada plantilla, tendrá un diseño profesional para sus reportes generados, podemos crear en este repositorio un archivo python con la plantilla para cada herramienta, y desde el pipeline poder conectarla. Luego, los +30 repositorios de aplicaciones de la empresa llamarán a estas plantillas usando la sintaxis uses: MiOrg/pipelines-centrales/.github/workflows/archivo.yml@main.
Los pipelines, deben ser universales, para cualquier tipo de lenguaje, un pipeline puede ser reutilizable para cualquier lenguaje.

Restricciones Arquitectónicas (CRÍTICAS):

Cero Configuración Extra: Los pipelines no deben requerir configuraciones adicionales en los repositorios cliente (ni tokens SaaS, ni licencias, ni Personal Access Tokens).

Modo Auditoría: Todos los pasos de escaneo deben incluir continue-on-error: true para que informen los hallazgos sin romper el pipeline de desarrollo.

Reportes Nativos o Seguros: Los flujos deben generar reportes legibles (HTML o PDF) que se suban como artefactos (actions/upload-artifact@v4), La carpeta de reportes, debe contener el nombre del repositorio analizado. NO uses acciones de terceros (ej. sarif-to-html-action) que puedan quedar obsoletas. Si una herramienta solo escupe JSON, usa un paso con un script en línea de python3 para convertirlo a HTML.

Bypass de Licencias: Para Gitleaks, NO uses la acción oficial gitleaks/gitleaks-action@v2 porque bloquea repositorios de organizaciones exigiendo licencia. Usa directamente la imagen de Docker zricethezav/gitleaks:latest.

Herramientas a implementar por etapa (Basadas en SSDLC):

Secretos: Gitleaks (vía Docker) y TruffleHog.

SAST: Semgrep (buscando OWASP Top 10 y Secretos, generando reporte ).

SCA: OWASP Dependency-Check (vía Docker, generando su reporte HTML nativo).

Contenedores: kicks, Hadolint (linter) y Trivy Image (usando la plantilla interna @/contrib/html.tpl descargada vía curl para evitar errores de path).

Tareas:

Redacta el código completo para los archivos YAML independientes que irán en el repositorio pipelines-centrales (ej. sec-secrets.yml, sec-sast.yml, sec-sca.yml, sec-containers.yml). Recuerda usar on: workflow_call.

Redacta un ejemplo de archivo .github/workflows/seguridad.yml de "consumidor", mostrando cómo uno de los repositorios de aplicaciones llamaría a estos workflows reutilizables.

Explica brevemente los pasos que debo seguir en la configuración de la organización de GitHub para permitir que los repositorios privados lean el repositorio central.

pipeline universal de referencia, del cual vamos a separar cada herramienta en un pipeline individual:
# ═══════════════════════════════════════════════════════
# SSDLC Security Pipeline — Equipo Cybersecurity
# GitHub Actions · Universal · Reporta pero no bloquea
# ═══════════════════════════════════════════════════════

name: SSDLC Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  workflow_dispatch: {}

permissions:
  contents: read
  security-events: write
  actions: read

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:

  # ══════════════════════════════════════
  # ETAPA 1 — PRE-COMMIT HOOKS (KICKS)
  # ══════════════════════════════════════

  kicks:
    name: "1 · Kicks — Pre-commit Hooks"
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Instalar pre-commit
        run: pip install pre-commit

      - name: Ejecutar hooks
        run: |
          if [ -f .pre-commit-config.yaml ]; then
            echo "Archivo .pre-commit-config.yaml encontrado"
            pre-commit run --all-files --show-diff-on-failure 2>&1 | tee kicks-output.txt || true
          else
            echo "No se encontro .pre-commit-config.yaml en el repositorio." > kicks-output.txt
            echo "Para activar esta etapa, crear el archivo con los hooks deseados." >> kicks-output.txt
            echo "Ejemplo minimo:" >> kicks-output.txt
            echo "" >> kicks-output.txt
            echo "repos:" >> kicks-output.txt
            echo "  - repo: https://github.com/pre-commit/pre-commit-hooks" >> kicks-output.txt
            echo "    rev: v4.6.0" >> kicks-output.txt
            echo "    hooks:" >> kicks-output.txt
            echo "      - id: trailing-whitespace" >> kicks-output.txt
            echo "      - id: end-of-file-fixer" >> kicks-output.txt
            echo "      - id: check-yaml" >> kicks-output.txt
            echo "      - id: check-added-large-files" >> kicks-output.txt
            echo "      - id: detect-private-key" >> kicks-output.txt
          fi

      - name: Generar reporte HTML
        if: always()
        env:
          REPO: ${{ github.repository }}
          SHA: ${{ github.sha }}
        run: |
          python3 << 'PYEOF'
          import os, html
          from datetime import datetime

          repo = os.environ["REPO"]
          sha = os.environ["SHA"]
          fecha = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

          output = ""
          if os.path.exists("kicks-output.txt"):
              output = open("kicks-output.txt").read()

          has_config = os.path.exists(".pre-commit-config.yaml")
          status_class = "pass" if has_config else "warn"
          status_text = "Hooks ejecutados" if has_config else "Sin configuracion de pre-commit"

          contenido = html.escape(output)

          report = f"""<!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Kicks Report</title>
            <style>
              body {{ font-family: system-ui; background: #0d1117; color: #c9d1d9; padding: 40px; }}
              h1 {{ color: #58a6ff; }}
              .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
              .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 13px; }}
              .pass {{ background: #0d3321; color: #3fb950; border: 1px solid #238636; }}
              .warn {{ background: #3d2e08; color: #d29922; border: 1px solid #9e6a03; }}
              pre {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; overflow-x: auto; font-size: 13px; line-height: 1.6; margin-top: 20px; white-space: pre-wrap; word-wrap: break-word; }}
            </style>
          </head>
          <body>
            <h1>Pre-commit Hooks Report</h1>
            <div class="meta">
              Repositorio: {repo}<br>
              Commit: {sha}<br>
              Fecha: {fecha}
            </div>
            <span class="badge {status_class}">{status_text}</span>
            <pre>{contenido}</pre>
          </body>
          </html>"""

          with open("kicks-report.html", "w") as f:
              f.write(report)
          PYEOF

      - name: Subir reporte
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: report-kicks
          path: kicks-report.html
          retention-days: 30

  # ══════════════════════════════════════
  # ETAPA 2 — GITLEAKS
  # Deteccion de secretos en el codigo
  # ══════════════════════════════════════

  gitleaks:
    name: "2 · Gitleaks — Secrets Scan"
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Ejecutar Gitleaks
        run: |
          docker run --rm \
            -v "$PWD":/repo \
            zricethezav/gitleaks:latest \
            detect --source /repo \
            --verbose \
            --report-format json \
            --report-path /repo/gitleaks-results.json \
            --exit-code 0 || true

      - name: Generar reporte HTML
        if: always()
        env:
          REPO: ${{ github.repository }}
          SHA: ${{ github.sha }}
        run: |
          python3 << 'PYEOF'
          import json, html, os
          from datetime import datetime

          repo = os.environ["REPO"]
          sha = os.environ["SHA"]

          results = []
          if os.path.exists("gitleaks-results.json"):
              try:
                  data = json.load(open("gitleaks-results.json"))
                  if isinstance(data, list):
                      results = data
              except:
                  pass

          count = len(results)
          status_class = "fail" if count > 0 else "pass"
          status_text = f"{count} secreto(s) detectado(s)" if count > 0 else "Sin secretos detectados"

          rows = ""
          for r in results:
              desc = html.escape(str(r.get("Description", "N/A")))
              file = html.escape(str(r.get("File", "N/A")))
              line = r.get("StartLine", "?")
              rule = html.escape(str(r.get("RuleID", "N/A")))
              match = html.escape(str(r.get("Match", ""))[:60] + "..." if len(str(r.get("Match",""))) > 60 else str(r.get("Match","")))
              rows += f"<tr><td>{rule}</td><td>{file}:{line}</td><td>{desc}</td><td><code>{match}</code></td></tr>\n"

          report = f"""<!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Gitleaks Report</title>
            <style>
              body {{ font-family: system-ui; background: #0d1117; color: #c9d1d9; padding: 40px; }}
              h1 {{ color: #58a6ff; }}
              .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
              .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 13px; }}
              .pass {{ background: #0d3321; color: #3fb950; border: 1px solid #238636; }}
              .fail {{ background: #3d1114; color: #f85149; border: 1px solid #da3633; }}
              table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
              th {{ text-align: left; padding: 10px; background: #161b22; color: #58a6ff; border-bottom: 1px solid #30363d; }}
              td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 13px; }}
              tr:hover {{ background: #161b22; }}
              code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 11px; color: #f85149; }}
            </style>
          </head>
          <body>
            <h1>Gitleaks — Secrets Scan Report</h1>
            <div class="meta">
              Repositorio: {repo}<br>
              Commit: {sha}<br>
              Fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
            </div>
            <span class="badge {status_class}">{status_text}</span>
            {"<table><tr><th>Regla</th><th>Archivo:Linea</th><th>Descripcion</th><th>Match</th></tr>" + rows + "</table>" if rows else ""}
          </body>
          </html>"""

          with open("gitleaks-report.html", "w") as f:
              f.write(report)
          PYEOF

      - name: Subir reporte
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: report-gitleaks
          path: gitleaks-report.html
          retention-days: 30

  # ══════════════════════════════════════
  # ETAPA 3 — OWASP DEPENDENCY-CHECK
  # Analisis de dependencias contra NVD
  # ══════════════════════════════════════

  dependency-check:
    name: "3 · Dependency-Check — SCA"
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4

      - name: Crear directorio de reportes
        run: mkdir -p "$PWD/dc-reports"

      - name: Ejecutar OWASP Dependency-Check
        run: |
          docker run --rm \
            -v "$PWD":/src \
            -v "$PWD/dc-reports":/report \
            -e user=$UID \
            owasp/dependency-check:latest \
            --project "${{ github.repository }}" \
            --scan /src \
            --format HTML \
            --format JSON \
            --out /report \
            --failOnCVSS 99 \
            --enableRetired \
            --disableAssembly || true

      - name: Verificar reportes generados
        if: always()
        run: |
          echo "=== Contenido de dc-reports ==="
          ls -la dc-reports/ 2>/dev/null || echo "Directorio vacio"
          # Si no se genero el HTML, crear uno basico desde el JSON
          if [ ! -f dc-reports/dependency-check-report.html ]; then
            echo "HTML no generado, intentando crear desde JSON..."
            python3 << 'PYEOF'
          import json, html, os
          from datetime import datetime

          repo = os.environ.get("REPO", "N/A")
          sha = os.environ.get("SHA", "N/A")

          vulns = []
          json_path = "dc-reports/dependency-check-report.json"
          if os.path.exists(json_path):
              try:
                  data = json.load(open(json_path))
                  for dep in data.get("dependencies", []):
                      for v in dep.get("vulnerabilities", []):
                          v["_dep"] = dep.get("fileName", "?")
                          vulns.append(v)
              except:
                  pass

          count = len(vulns)
          status_class = "fail" if count > 0 else "pass"
          status_text = f"{count} vulnerabilidad(es)" if count > 0 else "Sin vulnerabilidades"

          rows = ""
          for v in sorted(vulns, key=lambda x: x.get("cvssv3",{}).get("baseScore",0), reverse=True)[:100]:
              sev = v.get("severity","?")
              name = html.escape(v.get("name","?"))
              dep = html.escape(v.get("_dep","?"))
              score = v.get("cvssv3",{}).get("baseScore", v.get("cvssv2",{}).get("score","?"))
              desc_raw = v.get("description","")[:120]
              desc = html.escape(desc_raw)
              sev_color = "#f85149" if sev in ("CRITICAL","HIGH") else "#d29922" if sev == "MEDIUM" else "#8b949e"
              rows += f'<tr><td style="color:{sev_color};font-weight:700">{html.escape(sev)}</td><td>{score}</td><td>{name}</td><td>{dep}</td><td>{desc}</td></tr>\n'

          report = f"""<!DOCTYPE html>
          <html><head><meta charset="UTF-8"><title>Dependency-Check Report</title>
          <style>
            body {{ font-family: system-ui; background: #0d1117; color: #c9d1d9; padding: 40px; }}
            h1 {{ color: #58a6ff; }}
            .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 13px; }}
            .pass {{ background: #0d3321; color: #3fb950; border: 1px solid #238636; }}
            .fail {{ background: #3d1114; color: #f85149; border: 1px solid #da3633; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ text-align: left; padding: 10px; background: #161b22; color: #58a6ff; border-bottom: 1px solid #30363d; }}
            td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; font-size: 12px; }}
            tr:hover {{ background: #161b22; }}
          </style></head>
          <body>
            <h1>OWASP Dependency-Check — SCA Report</h1>
            <div class="meta">Repositorio: {repo}<br>Commit: {sha}<br>Fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
            <span class="badge {status_class}">{status_text}</span>
            {"<table><tr><th>Severidad</th><th>CVSS</th><th>CVE</th><th>Dependencia</th><th>Descripcion</th></tr>" + rows + "</table>" if rows else ""}
          </body></html>"""

          with open("dc-reports/dependency-check-report.html", "w") as f:
              f.write(report)
          PYEOF
          fi
        env:
          REPO: ${{ github.repository }}
          SHA: ${{ github.sha }}

      - name: Subir reportes
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: report-dependency-check
          path: dc-reports/
          retention-days: 30

  # ══════════════════════════════════════
  # ETAPA 4 — SEMGREP
  # SAST multi-lenguaje con OWASP Top 10
  # ══════════════════════════════════════

  semgrep:
    name: "4 · Semgrep — SAST"
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4

      - name: Instalar Semgrep
        run: pip install semgrep

      - name: Ejecutar Semgrep
        run: |
          semgrep \
            --config=p/owasp-top-ten \
            --config=p/secrets \
            --config=p/ci \
            --json \
            --output=semgrep-results.json \
            . || true

      - name: Generar SARIF desde JSON
        if: always()
        run: |
          semgrep \
            --config=p/owasp-top-ten \
            --config=p/secrets \
            --config=p/ci \
            --sarif \
            --output=semgrep-results.sarif \
            . || true

      - name: Generar reporte HTML
        if: always()
        env:
          REPO: ${{ github.repository }}
          SHA: ${{ github.sha }}
        run: |
          python3 << 'PYEOF'
          import json, html, os
          from datetime import datetime

          repo = os.environ["REPO"]
          sha = os.environ["SHA"]

          results = []
          errors = []
          if os.path.exists("semgrep-results.json"):
              try:
                  data = json.load(open("semgrep-results.json"))
                  results = data.get("results", [])
                  errors = data.get("errors", [])
              except Exception as e:
                  errors.append({"message": str(e)})

          count = len(results)
          sev_counts = {}
          for r in results:
              sev = r.get("extra", {}).get("severity", "UNKNOWN")
              sev_counts[sev] = sev_counts.get(sev, 0) + 1

          status_class = "fail" if count > 0 else "pass"
          status_text = f"{count} hallazgo(s)" if count > 0 else "Sin hallazgos"
          sev_summary = " | ".join([f"{k}: {v}" for k,v in sorted(sev_counts.items())])

          rows = ""
          for r in results[:100]:
              sev = html.escape(r.get("extra",{}).get("severity","?"))
              msg = html.escape(r.get("extra",{}).get("message","")[:150])
              check = html.escape(r.get("check_id",""))
              # Mostrar solo el nombre corto de la regla
              check_short = check.split(".")[-1] if "." in check else check
              file = html.escape(r.get("path","?"))
              line = r.get("start",{}).get("line","?")
              sev_color = "#f85149" if sev == "ERROR" else "#d29922" if sev == "WARNING" else "#8b949e"
              rows += f'<tr><td style="color:{sev_color};font-weight:600">{sev}</td><td title="{check}">{html.escape(check_short)}</td><td>{file}:{line}</td><td>{msg}</td></tr>\n'

          error_section = ""
          if errors:
              error_rows = ""
              for e in errors[:20]:
                  emsg = html.escape(str(e.get("message", e.get("msg", str(e))))[:200])
                  error_rows += f"<li>{emsg}</li>\n"
              error_section = f'<details style="margin-top:20px"><summary style="color:#d29922;cursor:pointer">Errores de Semgrep ({len(errors)})</summary><ul style="margin-top:10px;font-size:12px">{error_rows}</ul></details>'

          report = f"""<!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Semgrep SAST Report</title>
            <style>
              body {{ font-family: system-ui; background: #0d1117; color: #c9d1d9; padding: 40px; }}
              h1 {{ color: #58a6ff; }}
              .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
              .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 13px; margin-right: 8px; }}
              .pass {{ background: #0d3321; color: #3fb950; border: 1px solid #238636; }}
              .fail {{ background: #3d1114; color: #f85149; border: 1px solid #da3633; }}
              .info {{ background: #0d1d31; color: #58a6ff; border: 1px solid #1f6feb; font-size: 12px; }}
              table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
              th {{ text-align: left; padding: 10px; background: #161b22; color: #58a6ff; border-bottom: 1px solid #30363d; }}
              td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 12px; }}
              tr:hover {{ background: #161b22; }}
            </style>
          </head>
          <body>
            <h1>Semgrep — SAST Report</h1>
            <div class="meta">
              Repositorio: {repo}<br>
              Commit: {sha}<br>
              Fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}<br>
              Reglas: OWASP Top 10 + Secrets + CI
            </div>
            <span class="badge {status_class}">{status_text}</span>
            {"<span class='badge info'>" + sev_summary + "</span>" if sev_summary else ""}
            {"<table><tr><th>Severidad</th><th>Regla</th><th>Archivo:Linea</th><th>Descripcion</th></tr>" + rows + "</table>" if rows else ""}
            {error_section}
          </body>
          </html>"""

          with open("semgrep-report.html", "w") as f:
              f.write(report)
          print(f"Semgrep: {count} hallazgos, {len(errors)} errores")
          PYEOF

      - name: Subir SARIF a GitHub Security
        if: always() && hashFiles('semgrep-results.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep-results.sarif
        continue-on-error: true

      - name: Subir reporte HTML
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: report-semgrep
          path: semgrep-report.html
          retention-days: 30

  # ══════════════════════════════════════
  # ETAPA 5 — CODEQL
  # Solo si Advanced Security esta habilitado
  # Solo escanea lenguajes detectados
  # ══════════════════════════════════════

  codeql:
    name: "5 · CodeQL — Semantic SAST"
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4

      - name: Detectar lenguajes en el repo
        id: detect
        run: |
          LANGS=""
          # Go
          find . -name "*.go" -not -path "./.git/*" | head -1 | grep -q . && LANGS="${LANGS}go,"
          # Python
          find . -name "*.py" -not -path "./.git/*" | head -1 | grep -q . && LANGS="${LANGS}python,"
          # JavaScript/TypeScript
          find . -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" | grep -v node_modules | grep -v .git | head -1 | grep -q . && LANGS="${LANGS}javascript-typescript,"
          # Java/Kotlin
          find . -name "*.java" -o -name "*.kt" | grep -v .git | head -1 | grep -q . && LANGS="${LANGS}java-kotlin,"

          # Quitar coma final
          LANGS=$(echo "$LANGS" | sed 's/,$//')

          if [ -z "$LANGS" ]; then
            echo "No se detectaron lenguajes soportados por CodeQL"
            echo "found=false" >> $GITHUB_OUTPUT
            echo "langs=" >> $GITHUB_OUTPUT
          else
            echo "Lenguajes detectados: $LANGS"
            echo "found=true" >> $GITHUB_OUTPUT
            echo "langs=$LANGS" >> $GITHUB_OUTPUT
          fi

      - name: Inicializar CodeQL
        if: steps.detect.outputs.found == 'true'
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ steps.detect.outputs.langs }}
          queries: security-extended
        continue-on-error: true

      - name: Auto-build
        if: steps.detect.outputs.found == 'true'
        uses: github/codeql-action/autobuild@v3
        continue-on-error: true

      - name: Analizar
        if: steps.detect.outputs.found == 'true'
        uses: github/codeql-action/analyze@v3
        with:
          output: codeql-results
        continue-on-error: true

      - name: Generar reporte HTML
        if: always()
        env:
          REPO: ${{ github.repository }}
          SHA: ${{ github.sha }}
          LANGS: ${{ steps.detect.outputs.langs }}
          FOUND: ${{ steps.detect.outputs.found }}
        run: |
          python3 << 'PYEOF'
          import json, html, os, glob
          from datetime import datetime

          repo = os.environ["REPO"]
          sha = os.environ["SHA"]
          langs = os.environ.get("LANGS", "ninguno")
          found = os.environ.get("FOUND", "false")

          results = []
          sarif_files = glob.glob("codeql-results/**/*.sarif", recursive=True)
          for sf in sarif_files:
              try:
                  data = json.load(open(sf))
                  for run in data.get("runs", []):
                      results.extend(run.get("results", []))
              except:
                  pass

          count = len(results)

          if found == "false":
              status_class = "warn"
              status_text = "No se detectaron lenguajes soportados"
          elif count > 0:
              status_class = "fail"
              status_text = f"{count} hallazgo(s)"
          else:
              status_class = "pass"
              status_text = "Sin hallazgos"

          rows = ""
          for r in results[:80]:
              rule = html.escape(str(r.get("ruleId","?")))
              msg = html.escape(str(r.get("message",{}).get("text",""))[:120])
              locs = r.get("locations",[])
              loc_str = "?"
              if locs:
                  pl = locs[0].get("physicalLocation",{})
                  f = pl.get("artifactLocation",{}).get("uri","?")
                  ln = pl.get("region",{}).get("startLine","?")
                  loc_str = f"{f}:{ln}"
              level = r.get("level","note")
              lev_color = "#f85149" if level == "error" else "#d29922" if level == "warning" else "#8b949e"
              rows += f'<tr><td style="color:{lev_color};font-weight:600">{html.escape(level)}</td><td>{rule}</td><td>{html.escape(loc_str)}</td><td>{msg}</td></tr>\n'

          note = ""
          if found == "false":
              note = '<div style="margin-top:20px;padding:16px;background:#3d2e08;border:1px solid #9e6a03;border-radius:8px;font-size:13px;color:#d29922">CodeQL requiere <b>Advanced Security</b> habilitado en el repositorio (gratis para repos publicos, de pago para privados). Si tu repo es privado, puedes omitir esta etapa.</div>'

          report = f"""<!DOCTYPE html>
          <html>
          <head><meta charset="UTF-8"><title>CodeQL Report</title>
          <style>
            body {{ font-family: system-ui; background: #0d1117; color: #c9d1d9; padding: 40px; }}
            h1 {{ color: #58a6ff; }}
            .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 13px; }}
            .pass {{ background: #0d3321; color: #3fb950; border: 1px solid #238636; }}
            .fail {{ background: #3d1114; color: #f85149; border: 1px solid #da3633; }}
            .warn {{ background: #3d2e08; color: #d29922; border: 1px solid #9e6a03; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ text-align: left; padding: 10px; background: #161b22; color: #58a6ff; border-bottom: 1px solid #30363d; }}
            td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 12px; }}
            tr:hover {{ background: #161b22; }}
          </style></head>
          <body>
            <h1>CodeQL — Semantic SAST</h1>
            <div class="meta">Repositorio: {repo}<br>Commit: {sha}<br>Fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}<br>Lenguajes: {html.escape(langs) if langs else 'ninguno detectado'}</div>
            <span class="badge {status_class}">{status_text}</span>
            {note}
            {"<table><tr><th>Nivel</th><th>Regla</th><th>Archivo</th><th>Descripcion</th></tr>" + rows + "</table>" if rows else ""}
          </body></html>"""

          with open("codeql-report.html", "w") as f:
              f.write(report)
          PYEOF

      - name: Subir reporte
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: report-codeql
          path: codeql-report.html
          retention-days: 30

  # ══════════════════════════════════════
  # ETAPA 6 — TRIVY IMAGE
  # CVEs en imagen Docker
  # ══════════════════════════════════════

  trivy-image:
    name: "6 · Trivy — Container Scan"
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4

      - name: Build imagen Docker
        run: |
          if [ -f Dockerfile ]; then
            docker build -t local-scan:latest . || true
          else
            echo "No Dockerfile encontrado, usando imagen base"
            echo "FROM alpine:latest" | docker build -t local-scan:latest -
          fi

      - name: Trivy — Escanear imagen (JSON)
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$PWD":/output \
            aquasec/trivy:latest image \
              --severity LOW,MEDIUM,HIGH,CRITICAL \
              --format json \
              --output /output/trivy-results.json \
              --exit-code 0 \
              local-scan:latest || true

      - name: Trivy — Generar HTML nativo
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$PWD":/output \
            aquasec/trivy:latest image \
              --severity LOW,MEDIUM,HIGH,CRITICAL \
              --format template \
              --template "@contrib/html.tpl" \
              --output /output/trivy-report.html \
              --exit-code 0 \
              local-scan:latest || true
        continue-on-error: true

      - name: Fallback reporte HTML
        if: always()
        env:
          REPO: ${{ github.repository }}
          SHA: ${{ github.sha }}
        run: |
          if [ ! -s trivy-report.html ]; then
            python3 << 'PYEOF'
          import json, html, os
          from datetime import datetime

          repo = os.environ["REPO"]
          sha = os.environ["SHA"]

          results = []
          if os.path.exists("trivy-results.json"):
              try:
                  data = json.load(open("trivy-results.json"))
                  if isinstance(data, dict):
                      for r in data.get("Results", []):
                          for v in r.get("Vulnerabilities", []):
                              v["_target"] = r.get("Target", "?")
                              results.append(v)
              except:
                  pass

          count = len(results)
          crit = sum(1 for r in results if r.get("Severity") == "CRITICAL")
          high = sum(1 for r in results if r.get("Severity") == "HIGH")
          med = sum(1 for r in results if r.get("Severity") == "MEDIUM")
          low = sum(1 for r in results if r.get("Severity") == "LOW")

          rows = ""
          for r in sorted(results, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.get("Severity",""),4))[:150]:
              sev = r.get("Severity","?")
              sev_color = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#8b949e"}.get(sev,"#8b949e")
              vid = html.escape(r.get("VulnerabilityID","?"))
              pkg = html.escape(r.get("PkgName","?"))
              installed = html.escape(r.get("InstalledVersion","?"))
              fixed = html.escape(r.get("FixedVersion","N/A"))
              target = html.escape(r.get("_target","?"))
              rows += f'<tr><td style="color:{sev_color};font-weight:700">{sev}</td><td>{vid}</td><td>{pkg}</td><td>{installed}</td><td>{fixed}</td><td>{target}</td></tr>\n'

          report = f"""<!DOCTYPE html>
          <html><head><meta charset="UTF-8"><title>Trivy Image Report</title>
          <style>
            body {{ font-family: system-ui; background: #0d1117; color: #c9d1d9; padding: 40px; }}
            h1 {{ color: #58a6ff; }}
            .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 13px; margin-right: 6px; }}
            .crit {{ background: #3d1114; color: #f85149; border: 1px solid #da3633; }}
            .high {{ background: #3d2e08; color: #d29922; border: 1px solid #9e6a03; }}
            .med {{ background: #0d1d31; color: #58a6ff; border: 1px solid #1f6feb; }}
            .low {{ background: #1c1c1c; color: #8b949e; border: 1px solid #30363d; }}
            .pass {{ background: #0d3321; color: #3fb950; border: 1px solid #238636; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ text-align: left; padding: 10px; background: #161b22; color: #58a6ff; border-bottom: 1px solid #30363d; }}
            td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; font-size: 12px; }}
            tr:hover {{ background: #161b22; }}
          </style></head>
          <body>
            <h1>Trivy — Container Image Scan</h1>
            <div class="meta">Repositorio: {repo}<br>Commit: {sha}<br>Fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
            <span class="badge crit">CRITICAL: {crit}</span>
            <span class="badge high">HIGH: {high}</span>
            <span class="badge med">MEDIUM: {med}</span>
            <span class="badge low">LOW: {low}</span>
            {"<span class='badge pass'>Sin vulnerabilidades</span>" if count == 0 else ""}
            {"<table><tr><th>Severidad</th><th>CVE</th><th>Paquete</th><th>Instalada</th><th>Corregida</th><th>Target</th></tr>" + rows + "</table>" if rows else ""}
          </body></html>"""

          with open("trivy-report.html", "w") as f:
              f.write(report)
          PYEOF
          fi

      - name: Subir reporte
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: report-trivy-image
          path: trivy-report.html
          retention-days: 30

  # ══════════════════════════════════════
  # RESUMEN
  # ══════════════════════════════════════

  summary:
    name: "Resumen de Seguridad"
    runs-on: ubuntu-latest
    if: always()
    needs:
      - kicks
      - gitleaks
      - dependency-check
      - semgrep
      - codeql
      - trivy-image
    steps:
      - name: Generar resumen
        run: |
          cat >> $GITHUB_STEP_SUMMARY << 'EOF'
          ## SSDLC Security Pipeline — Resumen

          | # | Etapa | Herramienta | Estado |
          |---|-------|-------------|--------|
          | 1 | Pre-commit Hooks | Kicks | ${{ needs.kicks.result == 'success' && '✅ OK' || '⚠️ Revisar' }} |
          | 2 | Secrets Scan | Gitleaks | ${{ needs.gitleaks.result == 'success' && '✅ OK' || '⚠️ Revisar' }} |
          | 3 | SCA | Dependency-Check | ${{ needs.dependency-check.result == 'success' && '✅ OK' || '⚠️ Revisar' }} |
          | 4 | SAST | Semgrep | ${{ needs.semgrep.result == 'success' && '✅ OK' || '⚠️ Revisar' }} |
          | 5 | Semantic SAST | CodeQL | ${{ needs.codeql.result == 'success' && '✅ OK' || '⚠️ Revisar' }} |
          | 6 | Container Scan | Trivy | ${{ needs.trivy-image.result == 'success' && '✅ OK' || '⚠️ Revisar' }} |

          > Reportes HTML en **Artifacts** de este workflow run.
          >
          > **Equipo Cybersecurity** · Pipeline informativo — reporta pero no bloquea.
          EOF
para kicks, corrijamos este error: No se encontro .pre-commit-config.yaml en el repositorio.
Para activar esta etapa, crear el archivo con los hooks deseados.
Ejemplo minimo:

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: detect-private-key

en dependency check: Error:  Error updating the NVD Data
org.owasp.dependencycheck.data.update.exception.UpdateException: Error updating the NVD Data
	at org.owasp.dependencycheck.data.update.NvdApiDataSource.processApi(NvdApiDataSource.java:387)
	at org.owasp.dependencycheck.data.update.NvdApiDataSource.update(NvdApiDataSource.java:128)
	at org.owasp.dependencycheck.Engine.doUpdates(Engine.java:887)
	at org.owasp.dependencycheck.Engine.initializeAndUpdateDatabase(Engine.java:692)
	at org.owasp.dependencycheck.Engine.analyzeDependencies(Engine.java:619)
	at org.owasp.dependencycheck.App.runScan(App.java:269)
	at org.owasp.dependencycheck.App.run(App.java:201)
	at org.owasp.dependencycheck.App.main(App.java:92)
Caused by: io.github.jeremylong.openvulnerability.client.nvd.NvdApiException: NVD Returned Status Code: 429
	at io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient._next(NvdCveClient.java:445)
	at io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient.next(NvdCveClient.java:356)
	at org.owasp.dependencycheck.data.update.NvdApiDataSource.processApi(NvdApiDataSource.java:343)
	... 7 common frames omitted
Error:  Failed to process CVE-2014-6456
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-6456'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 201611680 (length -1), read 0, remaining 512 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-7661
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-7661'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 249636380 (length -1), read 0, remaining 512 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-7663
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-7663'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 201549609 (length -1), read 0, remaining 384 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-7668
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-7668'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 198739977 (length -1), read 0, remaining 512 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-7670
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-7670'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 235319944 (length -1), read 0, remaining 768 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-7674
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-7674'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 255612565 (length -1), read 0, remaining 768 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-6457
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-6457'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 201615738 (length -1), read 0, remaining 768 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-7677
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-7677'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 196272430 (length -1), read 0, remaining 768 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-6460
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-6460'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 162466459 (length -1), read 0, remaining 768 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-7685
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-7685'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 105959245 (length -1), read 0, remaining 384 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)
Error:  Failed to process CVE-2014-6461
org.owasp.dependencycheck.data.nvdcve.DatabaseException: Error updating 'CVE-2014-6461'; General error: "org.h2.mvstore.MVStoreException: Reading from file sun.nio.ch.FileChannelImpl@6f79880d failed at 163929976 (length -1), read 0, remaining 768 [2.4.240/1]"; SQL statement:
SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=? [50000-240]
	at org.owasp.dependencycheck.data.nvdcve.CveDB.updateVulnerability(CveDB.java:1104)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.updateCveDb(NvdApiProcessor.java:119)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:96)
	at org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor.call(NvdApiProcessor.java:40)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:328)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1090)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:614)
	at java.base/java.lang.Thread.run(Thread.java:1474)

    3 · Dependency-Check — SCA
The job has exceeded the maximum execution time of 6h0m0s

vamos a usar como referencia este repositorio, que sea una guia y ayuda, cuando queramos implementar herramientas: https://github.com/JakobTheDev/awesome-devsecops/blob/main/readme.md