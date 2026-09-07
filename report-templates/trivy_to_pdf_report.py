#!/usr/bin/env python3
"""
Generador PDF institucional para reportes JSON de Trivy (SCA/Containers/FS).
Uso: python3 trivy_to_pdf_report.py <json_report> <output_pdf> [logo_path]

Refactor: usa el branding común Template_SM_Ciber (branding_sm.py).
"""

import html
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

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


class TrivyReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte Trivy · SCA"
    CODIGO = "DevSecOps-TRIVY"

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
        self.results = []
        self.stats = {}
        self.styles = build_styles()

    def _page_callback(self):
        return page_decorations_factory(
            report_title=self.REPORT_TITLE,
            codigo=self.CODIGO,
            logo_path=self.logo_path,
        )

    def load_json_report(self):
        try:
            with open(self.json_report_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            self.results = self.data.get("Results", []) if isinstance(self.data, dict) else []
            print("✓ Reporte Trivy cargado exitosamente.")
        except Exception as e:
            print(f"✗ Error al cargar JSON Trivy: {str(e)}")
            sys.exit(1)

    def map_trivy_severity(self, raw):
        sev = (raw or "UNKNOWN").upper()
        if sev == "CRITICAL":
            return self.SEV_CRITICA
        if sev == "HIGH":
            return self.SEV_ALTA
        if sev == "MEDIUM":
            return self.SEV_MEDIA
        return self.SEV_BAJA

    def calculate_statistics(self):
        total_vulns = 0
        critical = high = medium = low = 0
        vuln_by_lib = defaultdict(int)
        vulnerable_targets = 0

        for result in self.results:
            vulns = result.get("Vulnerabilities", []) or []
            if vulns:
                vulnerable_targets += 1
            for v in vulns:
                total_vulns += 1
                sev = self.map_trivy_severity(v.get("Severity"))
                if sev == self.SEV_CRITICA:
                    critical += 1
                elif sev == self.SEV_ALTA:
                    high += 1
                elif sev == self.SEV_MEDIA:
                    medium += 1
                else:
                    low += 1
                vuln_by_lib[v.get("PkgName", "Desconocido")] += 1

        self.stats = {
            "total_targets": len(self.results),
            "vulnerable_targets": vulnerable_targets,
            "total_vulnerabilities": total_vulns,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "vuln_by_lib": dict(sorted(vuln_by_lib.items(), key=lambda x: x[1], reverse=True)),
        }

    def create_executive_summary(self):
        elements = [Paragraph("RESUMEN EJECUTIVO", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        total = self.stats["total_vulnerabilities"]
        passed = total == 0
        if passed:
            desc = ("El análisis universal de Trivy no detectó vulnerabilidades en el "
                    "código, contenedores o librerías. Los artefactos evaluados cumplen "
                    "los umbrales institucionales.")
        else:
            desc = ("Trivy interceptó librerías o dependencias con vulnerabilidades "
                    "conocidas. El proyecto no cumple el Quality Gate y requiere "
                    "remediación según el detalle del reporte.")

        summary = (
            f"<b>Estado del análisis:</b> {status_html(passed)}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Archivos de dependencias analizados:</b> {self.stats['total_targets']}<br/>"
            f"<b>Archivos con vulnerabilidades:</b> {self.stats['vulnerable_targets']}<br/>"
            f"<b>Total de vulnerabilidades:</b> {total}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if total > 0:
            elements.append(Paragraph("Distribución por severidad", self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(self.stats, total=total))
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "Severidad reportada nativamente por la Trivy DB. Los porcentajes se "
                "calculan sobre el total de vulnerabilidades.",
                self.styles["Caption"],
            ))
        return elements

    def create_statistics_section(self):
        if self.stats["total_vulnerabilities"] == 0:
            return []
        elements = [PageBreak(),
                    Paragraph("DEPENDENCIAS MÁS VULNERABLES", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        top = list(self.stats["vuln_by_lib"].items())[:15]
        if top:
            data = [["Librería", "Vulnerabilidades"]]
            for name, cnt in top:
                data.append([name[:55], str(cnt)])
            elements.append(styled_secondary_table(data, [4.0 * inch, 1.5 * inch]))
        return elements

    def _extract_vulns_by_severity(self):
        by_sev = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for result in self.results:
            target = result.get("Target", "Unknown")
            for v in result.get("Vulnerabilities", []) or []:
                v["TargetFile"] = target
                by_sev[self.map_trivy_severity(v.get("Severity"))].append(v)
        return by_sev

    def _create_severity_block(self, severity, vulns):
        elements = [PageBreak(),
                    Paragraph(f"VULNERABILIDADES · {severity} ({len(vulns)})",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        for idx, v in enumerate(vulns, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.1 * inch))
            vid = html.escape(str(v.get("VulnerabilityID", "Sin ID")))
            pkg = html.escape(str(v.get("PkgName", "N/A")))
            installed = html.escape(str(v.get("InstalledVersion", "Desconocida")))
            fixed = html.escape(str(v.get("FixedVersion", "No disponible")))
            target = html.escape(str(v.get("TargetFile", "N/A")))
            desc = html.escape(str(v.get("Description") or v.get("Title") or "Sin descripción"))

            elements.append(Paragraph(
                f"<b>{idx}. {vid}</b> · {pkg}", self.styles["CustomHeading3"],
            ))
            details = (
                f"<b>Archivo:</b> {target}<br/>"
                f"<b>Librería:</b> {pkg} (instalada: {installed} · <b>solución:</b> {fixed})<br/>"
                f"<b>Descripción:</b> {desc[:280]}"
            )
            primary = v.get("PrimaryURL")
            if primary:
                details += f"<br/><b>Referencia:</b> {html.escape(str(primary))}"
            elements.append(Paragraph(details, self.styles["BodyJustified"]))
        return elements

    def create_findings_section(self):
        elements = []
        by_sev = self._extract_vulns_by_severity()
        for severity in [self.SEV_CRITICA, self.SEV_ALTA, self.SEV_MEDIA, self.SEV_BAJA]:
            vulns = by_sev[severity]
            if vulns:
                elements.extend(self._create_severity_block(severity, vulns))
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
                        Paragraph("REPORTE DE ANÁLISIS DE DEPENDENCIAS", self.styles["CustomTitle"]),
                        Paragraph("Trivy · Universal Scanner (SCA)", self.styles["CustomSubtitle"]),
                        Spacer(1, 0.3 * inch),
                        Paragraph(f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                                  self.styles["Caption"]),
                        Spacer(1, 0.4 * inch),
                        Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                        Spacer(1, 0.15 * inch)]
            for line in ["1. Resumen ejecutivo y distribución por severidad",
                         "2. Dependencias más vulnerables",
                         "3. Desglose de vulnerabilidades por severidad"]:
                elements.append(Paragraph(line, self.styles["BodyJustified"]))
            elements.append(PageBreak())
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF Trivy generado exitosamente: {self.pdf_output_path}")
        except Exception as e:
            print(f"✗ Error al generar PDF Trivy: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 trivy_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)
    logo = sys.argv[3] if len(sys.argv) > 3 else None
    TrivyReportGenerator(sys.argv[1], sys.argv[2], logo).generate_pdf()


if __name__ == "__main__":
    main()
