#!/usr/bin/env python3
"""
Generador PDF institucional para reportes JSON de Hadolint (Dockerfile Linter).
Uso: python3 hadolint_to_pdf_report.py <json_report> <output_pdf> [logo_path]

Refactor: usa el branding común Template_SM_Ciber (branding_sm.py).
"""

import html
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

# Forzar UTF-8 en stdout/stderr para evitar UnicodeEncodeError en Windows
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from branding_sm import (
    DOC_MARGINS,
    build_styles,
    page_decorations_factory,
    status_html,
    styled_secondary_table,
    tabla_distribucion_severidad,
)


class HadolintReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte Hadolint · Dockerfile"
    CODIGO = "DevSecOps-HADOLINT"

    def __init__(self, json_report_path, pdf_output_path, logo_filename=None):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path

        script_dir = os.path.dirname(os.path.abspath(__file__))
        if logo_filename:
            candidate = os.path.join(script_dir, logo_filename)
            self.logo_path = candidate if os.path.exists(candidate) else logo_filename
        else:
            self.logo_path = None

        self.data = None
        self.findings = []
        self.stats = {}
        self.styles = build_styles()

    def _page_callback(self):
        return page_decorations_factory(
            report_title=self.REPORT_TITLE,
            codigo=self.CODIGO,
            logo_path=self.logo_path,
        )

    # ------------------------------------------------------------------
    # Parseo (intacto)
    # ------------------------------------------------------------------
    def load_json_report(self):
        try:
            with open(self.json_report_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            self.findings = self.data if isinstance(self.data, list) else []
            print("✓ Reporte Hadolint cargado exitosamente.")
        except Exception as e:
            print(f"✗ Error al cargar JSON Hadolint: {str(e)}")
            sys.exit(1)

    def map_hadolint_severity(self, level):
        """
        Mapeo Hadolint → institucional:
            error   → ALTA    (problemas serios en Dockerfile)
            warning → MEDIA   (buenas prácticas ausentes)
            info    → BAJA    (sugerencias menores)
            style   → BAJA    (formato)
        """
        level = (level or "info").lower()
        if level == "error":
            return self.SEV_ALTA
        if level == "warning":
            return self.SEV_MEDIA
        return self.SEV_BAJA

    def calculate_statistics(self):
        critical = high = medium = low = 0
        by_file = defaultdict(int)
        by_code = defaultdict(int)

        for f in self.findings:
            severity = self.map_hadolint_severity(f.get("level"))
            if severity == self.SEV_CRITICA:
                critical += 1
            elif severity == self.SEV_ALTA:
                high += 1
            elif severity == self.SEV_MEDIA:
                medium += 1
            else:
                low += 1

            file_path = str(f.get("file", "Dockerfile"))
            by_file[file_path] += 1
            code = str(f.get("code", "UNKNOWN"))
            by_code[code] += 1

        self.stats = {
            "total_findings": len(self.findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "files_scanned": len(by_file),
            "findings_by_file": dict(sorted(by_file.items(), key=lambda x: x[1], reverse=True)),
            "top_codes": dict(sorted(by_code.items(), key=lambda x: x[1], reverse=True)),
        }

    # ------------------------------------------------------------------
    # Secciones del PDF
    # ------------------------------------------------------------------
    def create_executive_summary(self):
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles["CustomHeading2"]))
        elements.append(Spacer(1, 0.15 * inch))

        total = self.stats["total_findings"]
        passed = total == 0

        if passed:
            desc = (
                "El análisis de Hadolint no detectó violaciones de mejores prácticas "
                "en los Dockerfiles del repositorio, o no se encontraron Dockerfiles. "
                "Los archivos evaluados cumplen con los estándares corporativos."
            )
        else:
            desc = (
                "Hadolint identificó violaciones de mejores prácticas en los Dockerfiles. "
                "Es necesario revisar y corregir estos hallazgos para asegurar la "
                "construcción de imágenes seguras y minimizar la superficie de ataque."
            )

        summary = (
            f"<b>Estado del análisis:</b> {status_html(passed, label_fail='REVISAR')}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Dockerfiles analizados:</b> {self.stats['files_scanned']}<br/>"
            f"<b>Total de hallazgos:</b> {total}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if total > 0:
            elements.append(Paragraph("Distribución por severidad", self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(self.stats, total=total))
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "Mapeo Hadolint → institucional: error → ALTA · warning → MEDIA · "
                "info/style → BAJA. Los porcentajes se calculan sobre el total de hallazgos.",
                self.styles["Caption"],
            ))

        return elements

    def create_statistics_section(self):
        if self.stats["total_findings"] == 0:
            return []
        elements = [PageBreak(),
                    Paragraph("CÓDIGOS HADOLINT MÁS FRECUENTES", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        top_codes = list(self.stats["top_codes"].items())[:15]
        if top_codes:
            data = [["Código", "Ocurrencias"]]
            for code, cnt in top_codes:
                data.append([code, str(cnt)])
            elements.append(styled_secondary_table(data, [3.5 * inch, 1.5 * inch]))

        return elements

    def _extract_findings_by_severity(self):
        by_sev = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for f in self.findings:
            by_sev[self.map_hadolint_severity(f.get("level"))].append(f)
        return by_sev

    def _create_severity_block(self, severity, findings):
        elements = [PageBreak(),
                    Paragraph(f"HALLAZGOS DOCKERFILE · {severity} ({len(findings)})",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        for idx, f in enumerate(findings, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.1 * inch))
            code = html.escape(str(f.get("code", "?")))
            file_path = html.escape(str(f.get("file", "?")).lstrip("./"))
            line = f.get("line", "?")
            col = f.get("column", "?")
            message = html.escape(str(f.get("message", ""))[:300])
            level = html.escape(str(f.get("level", "?")).upper())

            elements.append(Paragraph(
                f"<b>{idx}. [{code}]</b> {message[:120]}",
                self.styles["CustomHeading3"],
            ))
            details = (
                f"<b>Archivo:</b> {file_path} (línea {line}, col {col})<br/>"
                f"<b>Nivel nativo Hadolint:</b> {level}<br/>"
                f"<b>Descripción:</b> {message}<br/>"
                f"<b>Referencia:</b> https://github.com/hadolint/hadolint/wiki/{code}"
            )
            elements.append(Paragraph(details, self.styles["BodyJustified"]))

        return elements

    def create_findings_section(self):
        elements = []
        by_sev = self._extract_findings_by_severity()
        for severity in [self.SEV_CRITICA, self.SEV_ALTA, self.SEV_MEDIA, self.SEV_BAJA]:
            findings = by_sev[severity]
            if findings:
                elements.extend(self._create_severity_block(severity, findings))
        return elements

    def generate_pdf(self):
        try:
            self.load_json_report()
            self.calculate_statistics()

            doc = SimpleDocTemplate(
                self.pdf_output_path, pagesize=letter,
                title=self.REPORT_TITLE, **DOC_MARGINS,
            )
            elements = [Spacer(1, 1.4 * inch),
                        Paragraph("REPORTE DE ANÁLISIS DE DOCKERFILE", self.styles["CustomTitle"]),
                        Paragraph("Hadolint · Dockerfile Best Practices Linter",
                                  self.styles["CustomSubtitle"]),
                        Spacer(1, 0.3 * inch),
                        Paragraph(f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                                  self.styles["Caption"]),
                        Spacer(1, 0.4 * inch),
                        Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                        Spacer(1, 0.15 * inch)]
            for line in ["1. Resumen ejecutivo y distribución por severidad",
                         "2. Códigos Hadolint más frecuentes",
                         "3. Desglose de hallazgos por severidad"]:
                elements.append(Paragraph(line, self.styles["BodyJustified"]))
            elements.append(PageBreak())
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF Hadolint generado exitosamente: {self.pdf_output_path}")
        except Exception as e:
            print(f"✗ Error al generar PDF Hadolint: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 hadolint_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)
    logo = sys.argv[3] if len(sys.argv) > 3 else None
    HadolintReportGenerator(sys.argv[1], sys.argv[2], logo).generate_pdf()


if __name__ == "__main__":
    main()
