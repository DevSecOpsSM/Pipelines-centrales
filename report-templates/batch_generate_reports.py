#!/usr/bin/env python3
"""
Batch Report Generator — Consolidador de reportes SSDLC
========================================================

Orquesta los generators individuales de cada herramienta y produce:

  1. PDFs individuales por herramienta (Semgrep, Gitleaks, KICS, Hadolint,
     Trivy, Checkov, OWASP DC, SonarQube).
  2. UN PDF ejecutivo consolidado con visión global (resumen por herramienta,
     tabla CVSSv3 acumulada, top hallazgos globales, links a los detallados).

Input esperado (todos opcionales — el consolidador ignora los ausentes):

  <input-dir>/
    gitleaks-raw.json                 (sec-secrets)
    semgrep-raw.json                  (sec-sast)
    dependency-check-report.json      (sec-sca)
    checkov-raw.json                  (sec-iac-terraform · Checkov — primary)
    terraform-native-raw.json         (sec-iac-terraform · fmt+validate — opcional)
    tflint-raw.json                   (sec-iac-terraform · tflint — opcional)
    kics-results.json                 (sec-containers · KICS)
    hadolint-raw.json                 (sec-containers · Hadolint)
    trivy-raw.json                    (sec-containers · Trivy)
    sonar-issues.json                 (sec-sonarqube)
    sonar-hotspots.json               (sec-sonarqube — opcional, mejora contexto)
    sonar-qg.json                     (sec-sonarqube — opcional)

Uso:
  python3 batch_generate_reports.py \\
      --input-dir <path_con_jsons> \\
      --output-dir <path_donde_generar_pdfs> \\
      [--repo <nombre-repo>] \\
      [--sha <commit-sha>] \\
      [--logo <path_al_logo>]

Salidas en <output-dir>:
  01-executive-summary.pdf     ← PDF consolidado (portada + tabla global)
  02-gitleaks.pdf              ← si había gitleaks-raw.json
  03-semgrep.pdf               ← si había semgrep-raw.json
  ...
  batch-manifest.json          ← resumen máquina-legible del batch
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

# Forzar UTF-8 en stdout/stderr — runners Ubuntu ya son UTF-8 nativo, pero
# los generators tienen prints con ✓/✗ que crashean en Windows console (cp1252).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

# Reportlab para el PDF ejecutivo consolidado
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
)

# Branding común Template_SM_Ciber
from branding_sm import (
    DOC_MARGINS,
    build_styles,
    page_decorations_factory,
    status_html,
    styled_secondary_table,
    tabla_distribucion_severidad,
)


# ═══════════════════════════════════════════════════════════════════════════
# Mapa: qué JSON produce cada herramienta y qué generator ejecutarlo
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).resolve().parent

# tool_key → (json_filename, generator_module, tool_display_name, stage_number, sequence)
#
# NOTA sec-iac-terraform:
#   El workflow sec-iac-terraform corre 3 herramientas (fmt+validate, tflint,
#   Checkov). Aquí se representa como UN solo generator
#   `terraform_full_to_pdf_report` que recibe el JSON primario (checkov-raw.json)
#   y busca los otros 2 (terraform-native-raw.json, tflint-raw.json) en el
#   MISMO directorio. Los ausentes se saltan.
TOOL_CATALOG = [
    ("gitleaks",        "gitleaks-raw.json",              "gitleaks_to_pdf_report",        "Gitleaks (Secrets)",                        2),
    ("semgrep",         "semgrep-raw.json",               "semgrep_to_pdf_report",         "Semgrep (SAST)",                            3),
    ("owasp",           "dependency-check-report.json",   "owasp_to_pdf_report",           "OWASP Dependency-Check",                    4),
    ("terraform_full",  "checkov-raw.json",               "terraform_full_to_pdf_report",  "Terraform Full (fmt+validate+tflint+Checkov)", 5),
    ("kics",            "kics-results.json",              "kics_to_pdf_report",            "KICS (IaC Multi-format)",                   6),
    ("hadolint",        "hadolint-raw.json",              "hadolint_to_pdf_report",        "Hadolint (Dockerfile)",                     6),
    ("trivy",           "trivy-raw.json",                 "trivy_to_pdf_report",           "Trivy (Containers/FS)",                     6),
    ("sonarqube",       "sonar-issues.json",              "sonarqube_to_pdf_report",       "SonarQube (SAST+Coverage)",                 7),
]


# ═══════════════════════════════════════════════════════════════════════════
# Utilidades para leer counts por herramienta (usadas en el PDF consolidado)
# ═══════════════════════════════════════════════════════════════════════════

def _safe_load_json(path: Path) -> Optional[object]:
    if not path.exists():
        return None
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[WARN] No se pudo leer {path}: {exc}", file=sys.stderr)
        return None


def _count_gitleaks(data) -> dict:
    findings = data if isinstance(data, list) else []
    return {"critical": len(findings), "high": 0, "medium": 0, "low": 0, "info": 0,
            "total": len(findings)}


def _count_semgrep(data) -> dict:
    results = (data or {}).get("results", []) or []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        sev = (r.get("extra", {}) or {}).get("severity", "INFO").upper()
        if sev == "ERROR":
            counts["high"] += 1
        elif sev == "WARNING":
            counts["medium"] += 1
        else:
            counts["low"] += 1
    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
    return counts


def _count_owasp(data) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not data:
        return {**counts, "total": 0}
    deps = (data or {}).get("dependencies", []) or []
    for dep in deps:
        for v in dep.get("vulnerabilities", []) or []:
            sev = (v.get("severity") or "LOW").upper()
            if sev == "CRITICAL":
                counts["critical"] += 1
            elif sev == "HIGH":
                counts["high"] += 1
            elif sev == "MEDIUM":
                counts["medium"] += 1
            else:
                counts["low"] += 1
    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
    return counts


def _count_terraform_full(data, input_dir: Optional[Path] = None) -> dict:
    """
    Consolida los counts de las 3 herramientas del workflow sec-iac-terraform:
      - Checkov               (data — JSON primario recibido)
      - terraform-native      (fmt + validate, si terraform-native-raw.json existe)
      - tflint                (si tflint-raw.json existe)

    El JSON primario ES checkov-raw.json (por convención del TOOL_CATALOG).
    Los otros 2 se buscan en el mismo directorio.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # ── Checkov ──────────────────────────────────────────────────────────
    if data:
        reports = data if isinstance(data, list) else [data]
        for rep in reports:
            for c in (rep.get("results", {}) or {}).get("failed_checks", []) or []:
                sev = (c.get("severity") or "HIGH").upper()
                if sev == "CRITICAL":
                    counts["critical"] += 1
                elif sev == "HIGH":
                    counts["high"] += 1
                elif sev == "MEDIUM":
                    counts["medium"] += 1
                elif sev == "LOW":
                    counts["low"] += 1
                else:
                    counts["info"] += 1

    if input_dir is None:
        counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
        return counts

    # ── terraform-native (fmt + validate) ────────────────────────────────
    native = _safe_load_json(input_dir / "terraform-native-raw.json")
    if native:
        counts["info"] += len((native.get("fmt", {}) or {}).get("unformatted_files", []) or [])
        for entry in (native.get("validate", {}) or {}).get("by_dir", []) or []:
            for diag in entry.get("diagnostics", []) or []:
                sev = (diag.get("severity") or "info").lower()
                if sev == "error":
                    counts["critical"] += 1
                elif sev == "warning":
                    counts["low"] += 1
                else:
                    counts["info"] += 1

    # ── tflint ───────────────────────────────────────────────────────────
    tflint_raw = _safe_load_json(input_dir / "tflint-raw.json")
    if tflint_raw:
        entries = tflint_raw if isinstance(tflint_raw, list) else [tflint_raw]
        for entry in entries:
            for it in entry.get("issues", []) or []:
                sev = (it.get("rule", {}).get("severity") or "notice").lower()
                if sev == "error":
                    counts["medium"] += 1
                elif sev == "warning":
                    counts["low"] += 1
                else:
                    counts["info"] += 1

    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
    return counts


def _count_kics(data) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not data:
        return {**counts, "total": 0}
    queries = (data or {}).get("queries", []) or []
    for q in queries:
        sev = (q.get("severity") or "INFO").upper()
        if sev == "CRITICAL":
            counts["critical"] += 1
        elif sev == "HIGH":
            counts["high"] += 1
        elif sev == "MEDIUM":
            counts["medium"] += 1
        elif sev == "LOW":
            counts["low"] += 1
        else:
            counts["info"] += 1
    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
    return counts


def _count_hadolint(data) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = data if isinstance(data, list) else []
    for f in findings:
        lv = (f.get("level") or "info").lower()
        if lv == "error":
            counts["medium"] += 1   # mapeo institucional: error=medium
        elif lv == "warning":
            counts["low"] += 1
        else:
            counts["info"] += 1
    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
    return counts


def _count_trivy(data) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not data:
        return {**counts, "total": 0}
    for r in (data or {}).get("Results", []) or []:
        for v in r.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if sev == "CRITICAL":
                counts["critical"] += 1
            elif sev == "HIGH":
                counts["high"] += 1
            elif sev == "MEDIUM":
                counts["medium"] += 1
            else:
                counts["low"] += 1
    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
    return counts


def _count_sonarqube(data) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not data:
        return {**counts, "total": 0}
    for it in (data or {}).get("issues", []) or []:
        sev = (it.get("severity") or "MINOR").upper()
        if sev == "BLOCKER":
            counts["critical"] += 1
        elif sev == "CRITICAL":
            counts["high"] += 1
        elif sev == "MAJOR":
            counts["medium"] += 1
        elif sev == "MINOR":
            counts["low"] += 1
        else:
            counts["info"] += 1
    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))
    return counts


COUNTERS: dict[str, Callable] = {
    "gitleaks":       _count_gitleaks,
    "semgrep":        _count_semgrep,
    "owasp":          _count_owasp,
    "terraform_full": _count_terraform_full,
    "kics":           _count_kics,
    "hadolint":       _count_hadolint,
    "trivy":          _count_trivy,
    "sonarqube":      _count_sonarqube,
}


# ═══════════════════════════════════════════════════════════════════════════
# Orquestación: correr cada generator individual
# ═══════════════════════════════════════════════════════════════════════════

def resolve_logo_path(logo_arg: str) -> str:
    """
    Localiza el logo en varios sitios canónicos y devuelve su path ABSOLUTO.

    Orden de búsqueda:
      1. Si `logo_arg` es un path absoluto y existe, se usa tal cual
      2. `<report-templates>/<logo_arg>`      (compat con el uso original)
      3. `<repo-root>/image/<logo_arg>`       (nueva convención del proyecto)
      4. Si no se encuentra, se devuelve el nombre tal cual y los generators
         mostrarán la advertencia estándar "logo no encontrado" (no falla).
    """
    p = Path(logo_arg)
    if p.is_absolute() and p.exists():
        return str(p)

    candidates = [
        SCRIPT_DIR / logo_arg,                   # report-templates/<logo>
        SCRIPT_DIR.parent / "image" / logo_arg,  # <repo-root>/image/<logo>
    ]
    for c in candidates:
        if c.exists():
            resolved = str(c.resolve())
            print(f"[batch] Logo encontrado: {resolved}")
            return resolved

    print(f"[batch] Logo '{logo_arg}' NO encontrado en {SCRIPT_DIR} ni "
          f"{SCRIPT_DIR.parent / 'image'} — los PDFs se generarán sin logo",
          file=sys.stderr)
    return logo_arg   # el generator mostrará su warning y continuará


def run_individual_generators(
    input_dir: Path,
    output_dir: Path,
    logo_filename: str,
) -> list[dict]:
    """
    Corre cada X_to_pdf_report.py de las herramientas que tienen JSON presente.
    Devuelve una lista de dicts con el resultado por herramienta.
    """
    results: list[dict] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    for i, (tool_key, json_name, module_name, display_name, stage) in enumerate(TOOL_CATALOG, start=2):
        json_path = input_dir / json_name
        result = {
            "tool":         tool_key,
            "display_name": display_name,
            "stage":        stage,
            "json_present": json_path.exists(),
            "pdf_path":     None,
            "counts":       {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
            "status":       "skipped",
            "reason":       "",
        }

        if not json_path.exists():
            result["reason"] = f"JSON no encontrado: {json_name}"
            results.append(result)
            continue

        # Counts (para el consolidado). Los counters "normales" solo aceptan
        # data; los que consolidan múltiples JSONs (terraform_full) aceptan
        # además input_dir como kwarg opcional.
        try:
            data = _safe_load_json(json_path)
            try:
                result["counts"] = COUNTERS[tool_key](data, input_dir=input_dir)
            except TypeError:
                result["counts"] = COUNTERS[tool_key](data)
        except Exception as exc:
            print(f"[WARN] counts para {tool_key} fallaron: {exc}", file=sys.stderr)

        # Ejecutar el generator individual como subprocess
        script_path = SCRIPT_DIR / f"{module_name}.py"
        if not script_path.exists():
            result["reason"] = f"Generator faltante: {script_path.name}"
            results.append(result)
            continue

        pdf_name = f"{i:02d}-{tool_key}.pdf"
        pdf_path = output_dir / pdf_name

        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"  # los generators imprimen ✓/✗
            subprocess.run(
                [sys.executable, str(script_path), str(json_path), str(pdf_path), logo_filename],
                check=True,
                cwd=str(SCRIPT_DIR),
                env=env,
            )
            result["pdf_path"] = str(pdf_path.name)
            result["status"] = "ok"
        except subprocess.CalledProcessError as exc:
            result["status"] = "error"
            result["reason"] = f"Generator falló con exit code {exc.returncode}"

        results.append(result)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# PDF ejecutivo consolidado
# ═══════════════════════════════════════════════════════════════════════════

class ExecutiveSummaryPDF:
    """
    Genera el PDF ejecutivo consolidado con branding Template_SM_Ciber.
    Delega a branding_sm todo el layout (header/footer/watermark, estilos,
    tabla de distribución estándar).
    """

    REPORT_TITLE = "Reporte Ejecutivo · SSDLC"
    CODIGO = "DevSecOps-EJECUTIVO"

    # Tabla CVSSv3 institucional (misma que quality_gate_consolidator.py)
    THRESHOLDS = {
        "critical": (0,  "9.0-10.0", "24h calendario"),
        "high":     (0,  "7.0-8.9",  "7 días"),
        "medium":   (0,  "4.0-6.9",  "30 días"),
        "low":      (20, "0.1-3.9",  "90 días"),
        "info":     (50, "—",        "—"),
    }

    def __init__(self, results: list[dict], output_path: Path, repo: str, sha: str,
                 logo_filename: str = "Logo_Simon_Ultimo.png"):
        self.results = results
        self.output_path = output_path
        self.repo = repo
        self.sha = (sha or "")[:7]

        _p = Path(logo_filename)
        self.logo_path = str(_p if _p.is_absolute() else (SCRIPT_DIR / logo_filename))

        # Totales acumulados por severidad institucional (info se agrega a low
        # para la tabla estándar; queda separado en el manifest y en la sección
        # de umbrales por retro-compatibilidad con la tabla CVSSv3)
        self.totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in results:
            for sev in self.totals:
                self.totals[sev] += r["counts"].get(sev, 0)
        self.totals["total"] = sum(
            self.totals[k] for k in ("critical", "high", "medium", "low", "info")
        )

        # Stats para tabla_distribucion_severidad (fusiona info en low)
        self.stats_for_tabla = {
            "critical": self.totals["critical"],
            "high":     self.totals["high"],
            "medium":   self.totals["medium"],
            "low":      self.totals["low"] + self.totals["info"],
        }
        self.total_institucional = sum(self.stats_for_tabla.values())

        self.styles = build_styles()

    def _page_callback(self):
        return page_decorations_factory(
            report_title=self.REPORT_TITLE,
            codigo=self.CODIGO,
            logo_path=self.logo_path,
        )

    def _cover(self):
        elements = [Spacer(1, 1.4 * inch),
                    Paragraph("REPORTE EJECUTIVO SSDLC", self.styles["CustomTitle"]),
                    Paragraph("Análisis integrado de seguridad · Ciberseguridad",
                              self.styles["CustomSubtitle"]),
                    Spacer(1, 0.35 * inch)]
        elements.append(Paragraph(
            f"<b>Repositorio:</b> {self.repo}<br/>"
            f"<b>Commit:</b> {self.sha or '—'}<br/>"
            f"<b>Fecha:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}<br/>"
            f"<b>Metodología:</b> OWASP Top 10 + CVSSv3 + Quality Gate institucional",
            self.styles["BodyJustified"],
        ))
        elements.append(PageBreak())
        return elements

    def _toc(self):
        elements = [Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        for line in ["1. Veredicto global del Quality Gate y distribución",
                     "2. Resumen por herramienta",
                     "3. Umbrales CVSSv3 aplicados",
                     "4. SLA de remediación institucional",
                     "5. Reportes detallados por herramienta"]:
            elements.append(Paragraph(line, self.styles["BodyJustified"]))
        elements.append(PageBreak())
        return elements

    def _verdict(self):
        elements = [Paragraph("1. VEREDICTO GLOBAL DEL QUALITY GATE",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        breached = [
            (sev, self.totals[sev], threshold)
            for sev, (threshold, _c, _s) in self.THRESHOLDS.items()
            if self.totals[sev] > threshold
        ]
        passed = not breached

        if passed:
            desc = ("El análisis consolidado no detectó violaciones a los umbrales "
                    "CVSSv3 institucionales. El repositorio cumple los estándares "
                    "de seguridad definidos para su fase actual del SSDLC.")
        else:
            desc = ("Se detectaron uno o más umbrales excedidos según la tabla CVSSv3 "
                    "institucional. La remediación es obligatoria antes de continuar "
                    "al siguiente entorno.")

        elements.append(Paragraph(
            f"<b>Estado consolidado:</b> "
            f"{status_html(passed, label_fail='BLOQUEADO')}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Hallazgos totales acumulados:</b> {self.totals['total']}",
            self.styles["BodyJustified"],
        ))
        elements.append(Spacer(1, 0.2 * inch))

        if self.total_institucional > 0:
            elements.append(Paragraph("Distribución global por severidad",
                                      self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(
                self.stats_for_tabla, total=self.total_institucional))
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "Suma de hallazgos de todas las herramientas SSDLC ejecutadas. "
                "Los hallazgos INFO nativos se agrupan en BAJA para la tabla "
                "institucional; el desglose completo aparece en la sección de "
                "umbrales.",
                self.styles["Caption"],
            ))
        elements.append(PageBreak())
        return elements

    def _per_tool(self):
        elements = [Paragraph("2. RESUMEN POR HERRAMIENTA",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        rows = [["Etapa", "Herramienta", "Crít", "Alt", "Med", "Baj", "Info", "Total", "Estado"]]
        status_map = {"ok": "OK", "skipped": "Skipped", "error": "Error"}

        for r in sorted(self.results, key=lambda x: (x["stage"], x["display_name"])):
            counts = r["counts"]
            rows.append([
                str(r["stage"]),
                r["display_name"][:24],
                str(counts["critical"]),
                str(counts["high"]),
                str(counts["medium"]),
                str(counts["low"]),
                str(counts["info"]),
                str(counts["total"]),
                status_map.get(r["status"], "—"),
            ])

        rows.append([
            "—", "TOTAL ACUMULADO",
            str(self.totals["critical"]),
            str(self.totals["high"]),
            str(self.totals["medium"]),
            str(self.totals["low"]),
            str(self.totals["info"]),
            str(self.totals["total"]),
            "—",
        ])

        col_widths = [0.5 * inch, 1.7 * inch, 0.45 * inch, 0.45 * inch, 0.45 * inch,
                      0.45 * inch, 0.45 * inch, 0.55 * inch, 0.75 * inch]
        elements.append(styled_secondary_table(
            rows, col_widths, first_col_align="CENTER",
        ))
        elements.append(PageBreak())
        return elements

    def _thresholds(self):
        elements = [Paragraph("3. UMBRALES CVSSv3 APLICADOS",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        rows = [["Severidad", "CVSSv3", "Umbral bloqueo", "Hallazgos", "Estado"]]
        for sev, (threshold, cvss, _sla) in self.THRESHOLDS.items():
            count = self.totals[sev]
            rule = "> 0 bloquea" if threshold == 0 else f"> {threshold} bloquea"
            ok = count <= threshold if threshold > 0 else count == 0
            rows.append([sev.capitalize(), cvss, rule, str(count),
                         "OK" if ok else "BLOQUEA"])
        elements.append(styled_secondary_table(
            rows,
            [1.2 * inch, 1.2 * inch, 1.6 * inch, 1.0 * inch, 1.0 * inch],
            first_col_align="CENTER",
        ))
        elements.append(PageBreak())
        return elements

    def _sla(self):
        elements = [Paragraph("4. SLA DE REMEDIACIÓN INSTITUCIONAL",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        rows = [["Severidad", "CVSSv3", "SLA de remediación"]]
        for sev, (_t, cvss, sla) in self.THRESHOLDS.items():
            rows.append([sev.capitalize(), cvss, sla])
        elements.append(styled_secondary_table(
            rows,
            [1.5 * inch, 1.5 * inch, 2.5 * inch],
            first_col_align="LEFT",
            numeric_cols_center=False,
        ))
        elements.append(PageBreak())
        return elements

    def _references(self):
        elements = [Paragraph("5. REPORTES DETALLADOS POR HERRAMIENTA",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        elements.append(Paragraph(
            "Cada herramienta cuenta con un reporte PDF individual con el desglose "
            "completo de hallazgos, evidencia de código, referencias OWASP/CWE y "
            "sugerencias de remediación. Los PDFs se encuentran en el ZIP entregable "
            "adjunto a este documento.",
            self.styles["BodyJustified"],
        ))
        elements.append(Spacer(1, 0.2 * inch))

        rows = [["Herramienta", "Archivo PDF", "Estado"]]
        for r in sorted(self.results, key=lambda x: (x["stage"], x["display_name"])):
            pdf = r["pdf_path"] or "—"
            status = r["status"].capitalize()
            if r["status"] == "skipped" and r["reason"]:
                status = f"Skipped ({r['reason'][:32]})"
            rows.append([r["display_name"], pdf, status])
        elements.append(styled_secondary_table(
            rows,
            [2.4 * inch, 2.2 * inch, 1.8 * inch],
            first_col_align="LEFT",
            numeric_cols_center=False,
        ))
        return elements

    def generate(self):
        doc = SimpleDocTemplate(
            str(self.output_path), pagesize=letter,
            title=self.REPORT_TITLE, **DOC_MARGINS,
        )
        elements = []
        elements.extend(self._cover())
        elements.extend(self._toc())
        elements.extend(self._verdict())
        elements.extend(self._per_tool())
        elements.extend(self._thresholds())
        elements.extend(self._sla())
        elements.extend(self._references())

        page_cb = self._page_callback()
        doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
        print(f"✓ PDF ejecutivo consolidado generado: {self.output_path}")


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Consolida los reportes JSON de las herramientas SSDLC en "
                    "PDFs individuales + un PDF ejecutivo consolidado.",
    )
    p.add_argument("--input-dir", required=True, type=Path,
                   help="Directorio con los JSON raw de las herramientas")
    p.add_argument("--output-dir", required=True, type=Path,
                   help="Directorio donde generar los PDFs y el manifest")
    p.add_argument("--repo", default="unknown",
                   help="Nombre completo del repositorio (owner/repo)")
    p.add_argument("--sha", default="",
                   help="Commit SHA (para mostrar en la portada del ejecutivo)")
    p.add_argument("--logo", default="Logo_Simon_Ultimo.png",
                   help="Nombre del archivo de logo (buscado en report-templates/)")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # CRÍTICO: resolver a paths absolutos porque los subprocess corren con
    # cwd=SCRIPT_DIR y perderían la referencia con paths relativos.
    args.input_dir  = args.input_dir.resolve()
    args.output_dir = args.output_dir.resolve()

    if not args.input_dir.exists():
        print(f"[ERROR] input-dir no existe: {args.input_dir}", file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Resolver el logo a un path ABSOLUTO antes de propagarlo a los subprocess
    # y al ExecutiveSummaryPDF (los generators funcionan con nombre o con path
    # absoluto porque os.path.join respeta absolutos).
    logo_resolved = resolve_logo_path(args.logo)

    print(f"[batch] Input:  {args.input_dir}")
    print(f"[batch] Output: {args.output_dir}")
    print(f"[batch] Repo:   {args.repo}")
    print(f"[batch] Logo:   {logo_resolved}")
    print(f"[batch] JSONs disponibles en input-dir:")
    for p in sorted(args.input_dir.iterdir()):
        if p.is_file():
            print(f"          · {p.name} ({p.stat().st_size} bytes)")
    print()

    # 1. Generar PDFs individuales por herramienta
    results = run_individual_generators(args.input_dir, args.output_dir, logo_resolved)

    print("\n[batch] Resumen de generación individual:")
    for r in results:
        icon = "✓" if r["status"] == "ok" else ("·" if r["status"] == "skipped" else "✗")
        print(f"  {icon} {r['display_name']:<28} status={r['status']:<8} "
              f"pdf={r['pdf_path'] or '—'}")

    # 2. Generar PDF ejecutivo consolidado
    executive_path = args.output_dir / "01-executive-summary.pdf"
    exec_pdf = ExecutiveSummaryPDF(
        results=results,
        output_path=executive_path,
        repo=args.repo,
        sha=args.sha,
        logo_filename=logo_resolved,
    )
    try:
        exec_pdf.generate()
    except Exception as exc:
        print(f"[ERROR] fallo generando PDF ejecutivo: {exc}", file=sys.stderr)
        return 1

    # 3. Escribir manifest máquina-legible
    manifest = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "repo":             args.repo,
        "sha":              args.sha,
        "totals":           exec_pdf.totals,
        "tools":            results,
        "executive_pdf":    executive_path.name,
    }
    manifest_path = args.output_dir / "batch-manifest.json"
    with manifest_path.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    print(f"✓ Manifest generado: {manifest_path}")

    print(f"\n[batch] Totales acumulados: {exec_pdf.totals}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
