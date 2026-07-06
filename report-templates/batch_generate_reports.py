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
    checkov-raw.json                  (sec-iac-terraform)
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
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib import colors


# ═══════════════════════════════════════════════════════════════════════════
# Mapa: qué JSON produce cada herramienta y qué generator ejecutarlo
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).resolve().parent

# tool_key → (json_filename, generator_module, tool_display_name, stage_number, sequence)
TOOL_CATALOG = [
    ("gitleaks",   "gitleaks-raw.json",              "gitleaks_to_pdf_report",   "Gitleaks (Secrets)",       2),
    ("semgrep",    "semgrep-raw.json",               "semgrep_to_pdf_report",    "Semgrep (SAST)",           3),
    ("owasp",      "dependency-check-report.json",   "owasp_to_pdf_report",      "OWASP Dependency-Check",   4),
    ("checkov",    "checkov-raw.json",               "checkov_to_pdf_report",    "Checkov (IaC Terraform)",  5),
    ("kics",       "kics-results.json",              "kics_to_pdf_report",       "KICS (IaC Multi-format)",  6),
    ("hadolint",   "hadolint-raw.json",              "hadolint_to_pdf_report",   "Hadolint (Dockerfile)",    6),
    ("trivy",      "trivy-raw.json",                 "trivy_to_pdf_report",      "Trivy (Containers/FS)",    6),
    ("sonarqube",  "sonar-issues.json",              "sonarqube_to_pdf_report",  "SonarQube (SAST+Coverage)", 7),
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


def _count_checkov(data) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not data:
        return {**counts, "total": 0}
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
    "gitleaks":  _count_gitleaks,
    "semgrep":   _count_semgrep,
    "owasp":     _count_owasp,
    "checkov":   _count_checkov,
    "kics":      _count_kics,
    "hadolint":  _count_hadolint,
    "trivy":     _count_trivy,
    "sonarqube": _count_sonarqube,
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

        # Counts (para el consolidado)
        try:
            data = _safe_load_json(json_path)
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
    """Genera el PDF ejecutivo consolidado a partir de los results de todas las herramientas."""

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

        # logo_filename puede ser un nombre relativo (compat) o un path absoluto
        # ya resuelto por resolve_logo_path(). Si es absoluto se usa tal cual.
        _p = Path(logo_filename)
        self.logo_path = _p if _p.is_absolute() else (SCRIPT_DIR / logo_filename)
        self.test_type = "DevSecOps-Ejecutivo"

        self.totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in results:
            for sev in self.totals:
                self.totals[sev] += r["counts"].get(sev, 0)
        self.totals["total"] = sum(self.totals[k] for k in ("critical", "high", "medium", "low", "info"))

        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=26, textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30, alignment=TA_CENTER, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14, textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12, spaceBefore=12, fontName='Helvetica-Bold',
            borderColor=colors.HexColor('#00e5bd'), borderWidth=2,
            borderPadding=8, borderRadius=3,
        ))
        self.styles.add(ParagraphStyle(
            name='BodyJustified',
            parent=self.styles['BodyText'],
            alignment=TA_JUSTIFY, fontSize=10, leading=13,
            textColor=colors.HexColor('#2c3e50'),
        ))

    def draw_header(self, canvas, doc):
        canvas.saveState()
        width, height = letter

        if self.logo_path.exists():
            try:
                canvas.drawImage(str(self.logo_path), 40, height - 70, width=140, height=40,
                                 preserveAspectRatio=True, mask='auto')
            except Exception as exc:
                # Logo corrupto o no reconocible como imagen — continuar sin él
                print(f"[WARN] Logo no cargable ({exc}) — continuando sin logo", file=sys.stderr)

        data = [
            ['Código:', self.test_type],
            ['Vigente desde:', datetime.now().strftime('%d/%m/%Y')],
            ['Clasificación:', 'Confidencial'],
        ]
        t = Table(data, colWidths=[80, 100])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('SIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
        ]))
        t.wrapOn(canvas, width, height)
        t.drawOn(canvas, width - 220, height - 65)

        canvas.setStrokeColor(colors.HexColor('#00e5bd'))
        canvas.setLineWidth(1.5)
        canvas.line(40, height - 80, width - 40, height - 80)

        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.gray)
        canvas.drawCentredString(width / 2.0, 30, f"Página {canvas.getPageNumber()}")
        canvas.restoreState()

    def _cover(self):
        elements = [Spacer(1, 1.2 * inch)]
        elements.append(Paragraph("REPORTE EJECUTIVO", self.styles['CustomTitle']))
        elements.append(Paragraph("Análisis Integrado de Seguridad SSDLC",
                                  self.styles['Heading2']))
        elements.append(Spacer(1, 0.4 * inch))
        elements.append(Paragraph(
            f"<b>Repositorio:</b> {self.repo}<br/>"
            f"<b>Commit:</b> {self.sha or '—'}<br/>"
            f"<b>Fecha:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}<br/>"
            f"<b>Metodología:</b> OWASP Top 10 + CVSSv3 + Quality Gate Institucional",
            self.styles['BodyJustified'],
        ))
        elements.append(PageBreak())
        return elements

    def _toc(self):
        elements = [Paragraph("TABLA DE CONTENIDOS", self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]
        elements.append(Paragraph("1. Veredicto Global del Quality Gate", self.styles['Normal']))
        elements.append(Paragraph("2. Resumen por Herramienta", self.styles['Normal']))
        elements.append(Paragraph("3. Tabla CVSSv3 y Umbrales Aplicados", self.styles['Normal']))
        elements.append(Paragraph("4. SLA de Remediación Institucional", self.styles['Normal']))
        elements.append(Paragraph("5. Referencia a Reportes Detallados por Herramienta",
                                  self.styles['Normal']))
        elements.append(PageBreak())
        return elements

    def _verdict(self):
        elements = [Paragraph("1. VEREDICTO GLOBAL DEL QUALITY GATE",
                              self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]

        breached = []
        for sev, (threshold, _cvss, _sla) in self.THRESHOLDS.items():
            if self.totals[sev] > threshold:
                breached.append((sev, self.totals[sev], threshold))

        if not breached:
            status = "<font color='#27ae60'><b>APROBADO</b></font>"
            desc = ("El análisis consolidado no detectó violaciones a los umbrales "
                    "CVSSv3 institucionales. El repositorio cumple con los estándares "
                    "de seguridad definidos para su fase actual del SSDLC.")
        else:
            status = "<font color='#c0392b'><b>BLOQUEADO</b></font>"
            desc = ("Se detectaron uno o más umbrales excedidos según la tabla CVSSv3 "
                    "institucional. La remediación es obligatoria antes de continuar "
                    "al siguiente entorno.")

        summary = f"""
        <b>Estado consolidado:</b> {status}<br/>
        {desc}<br/><br/>
        <b>Hallazgos totales acumulados:</b> {self.totals['total']}<br/>
        <br/>
        <b>Distribución acumulada por severidad:</b><br/>
        • <font color='#c0392b'><b>Críticas:</b></font> {self.totals['critical']} hallazgos<br/>
        • <font color='#e74c3c'><b>Altas:</b></font> {self.totals['high']} hallazgos<br/>
        • <font color='#f39c12'><b>Medias:</b></font> {self.totals['medium']} hallazgos<br/>
        • <font color='#f1c40f'><b>Bajas:</b></font> {self.totals['low']} hallazgos<br/>
        • <font color='#95a5a6'><b>Info:</b></font> {self.totals['info']} hallazgos<br/>
        """
        elements.append(Paragraph(summary, self.styles['BodyJustified']))
        elements.append(PageBreak())
        return elements

    def _per_tool(self):
        elements = [Paragraph("2. RESUMEN POR HERRAMIENTA",
                              self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]

        header = ["Etapa", "Herramienta", "Crit", "Alt", "Med", "Baj", "Info", "Total", "Estado"]
        rows = [header]

        # Agrupar por stage number para orden visual
        for r in sorted(self.results, key=lambda x: (x["stage"], x["display_name"])):
            counts = r["counts"]
            status_map = {"ok": "OK", "skipped": "Skipped", "error": "Error"}
            rows.append([
                str(r["stage"]),
                r["display_name"][:22],
                str(counts["critical"]),
                str(counts["high"]),
                str(counts["medium"]),
                str(counts["low"]),
                str(counts["info"]),
                str(counts["total"]),
                status_map.get(r["status"], "—"),
            ])

        # Total row
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

        col_widths = [0.4 * inch, 1.7 * inch, 0.4 * inch, 0.4 * inch, 0.4 * inch,
                      0.4 * inch, 0.4 * inch, 0.5 * inch, 0.7 * inch]
        t = Table(rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        elements.append(t)
        elements.append(PageBreak())
        return elements

    def _thresholds(self):
        elements = [Paragraph("3. UMBRALES CVSSv3 APLICADOS",
                              self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]

        rows = [["Severidad", "CVSSv3", "Umbral Bloqueo", "Hallazgos", "Estado"]]
        for sev, (threshold, cvss, _sla) in self.THRESHOLDS.items():
            count = self.totals[sev]
            rule = "> 0 bloquea" if threshold == 0 else f"> {threshold} bloquea"
            passed = count <= threshold if threshold > 0 else count == 0
            status = "OK" if passed else "BLOQUEA"
            rows.append([sev.capitalize(), cvss, rule, str(count), status])

        t = Table(rows, colWidths=[1.2 * inch, 1.2 * inch, 1.5 * inch,
                                    1.0 * inch, 1.0 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        elements.append(t)
        elements.append(PageBreak())
        return elements

    def _sla(self):
        elements = [Paragraph("4. SLA DE REMEDIACIÓN INSTITUCIONAL",
                              self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]
        rows = [["Severidad", "CVSSv3", "SLA de Remediación"]]
        for sev, (_th, cvss, sla) in self.THRESHOLDS.items():
            rows.append([sev.capitalize(), cvss, sla])
        t = Table(rows, colWidths=[1.5 * inch, 1.5 * inch, 2.5 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        elements.append(t)
        elements.append(PageBreak())
        return elements

    def _references(self):
        elements = [Paragraph("5. REPORTES DETALLADOS POR HERRAMIENTA",
                              self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]
        elements.append(Paragraph(
            "Cada herramienta cuenta con un reporte PDF individual con el desglose "
            "completo de hallazgos, evidencia de código, referencias OWASP/CWE y "
            "sugerencias de remediación. Los PDFs se encuentran en el ZIP entregable "
            "adjunto a este documento.",
            self.styles['BodyJustified'],
        ))
        elements.append(Spacer(1, 0.2 * inch))

        rows = [["Herramienta", "Archivo PDF", "Estado"]]
        for r in sorted(self.results, key=lambda x: (x["stage"], x["display_name"])):
            pdf = r["pdf_path"] or "—"
            status = r["status"].capitalize()
            if r["status"] == "skipped" and r["reason"]:
                status = f"Skipped ({r['reason'][:30]})"
            rows.append([r["display_name"], pdf, status])
        t = Table(rows, colWidths=[2.2 * inch, 2.0 * inch, 2.0 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        elements.append(t)
        return elements

    def generate(self):
        doc = SimpleDocTemplate(
            str(self.output_path),
            pagesize=letter,
            topMargin=100, bottomMargin=50, rightMargin=40, leftMargin=40,
            title='Reporte Ejecutivo SSDLC Consolidado',
        )

        elements = []
        elements.extend(self._cover())
        elements.extend(self._toc())
        elements.extend(self._verdict())
        elements.extend(self._per_tool())
        elements.extend(self._thresholds())
        elements.extend(self._sla())
        elements.extend(self._references())

        doc.build(elements, onFirstPage=self.draw_header, onLaterPages=self.draw_header)
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
