#!/usr/bin/env python3
"""
Generador PDF institucional para reportes JSON de OWASP Dependency-Check.
Uso: python3 owasp_to_pdf_report.py <json_report> <output_pdf> [logo_path]

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


class OWASPReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte OWASP Dependency-Check · SCA"
    CODIGO = "DevSecOps-OWASP"

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
        self.dependencies = []
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
            self.dependencies = self.data.get("dependencies", [])
            print(f"✓ Reporte OWASP cargado: {len(self.dependencies)} dependencias")
        except Exception as e:
            print(f"✗ Error al cargar JSON OWASP: {str(e)}")
            sys.exit(1)

    def _get_vuln_cvss(self, vuln):
        if "cvssv3" in vuln:
            return vuln["cvssv3"].get("baseScore", 0)
        if "cvssv2" in vuln:
            return vuln["cvssv2"].get("score", 0)
        return 0

    def get_cvss_severity(self, cvss_score):
        try:
            score = float(cvss_score)
        except (ValueError, TypeError):
            return self.SEV_BAJA
        if score >= 9.0:
            return self.SEV_CRITICA
        if score >= 7.0:
            return self.SEV_ALTA
        if score >= 4.0:
            return self.SEV_MEDIA
        return self.SEV_BAJA

    def calculate_statistics(self):
        critical = high = medium = low = 0
        total_vulns = 0
        for dep in self.dependencies:
            for v in dep.get("vulnerabilities", []) or []:
                total_vulns += 1
                sev = self.get_cvss_severity(self._get_vuln_cvss(v))
                if sev == self.SEV_CRITICA:
                    critical += 1
                elif sev == self.SEV_ALTA:
                    high += 1
                elif sev == self.SEV_MEDIA:
                    medium += 1
                else:
                    low += 1

        self.stats = {
            "total_dependencies": len(self.dependencies),
            "vulnerable_dependencies": sum(
                1 for d in self.dependencies if d.get("vulnerabilities")
            ),
            "total_vulnerabilities": total_vulns,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }

    def create_executive_summary(self):
        elements = [Paragraph("RESUMEN EJECUTIVO", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        total = self.stats["total_vulnerabilities"]
        passed = total == 0

        if passed:
            desc = ("El escaneo SCA de OWASP Dependency-Check no detectó librerías "
                    "de terceros con vulnerabilidades conocidas (CVEs), asegurando "
                    "la integridad de la cadena de suministro.")
        else:
            desc = ("Se detectaron dependencias con CVEs documentadas. Es crítico "
                    "revisar y actualizar estas librerías a versiones parchadas.")

        summary = (
            f"<b>Estado del análisis:</b> {status_html(passed)}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Total de dependencias escaneadas:</b> {self.stats['total_dependencies']}<br/>"
            f"<b>Dependencias vulnerables:</b> {self.stats['vulnerable_dependencies']}<br/>"
            f"<b>Total de vulnerabilidades:</b> {total}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if total > 0:
            elements.append(Paragraph("Distribución por severidad (CVSS)",
                                      self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(self.stats, total=total))
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "Umbrales CVSSv3: CRÍTICA ≥ 9.0 · ALTA ≥ 7.0 · MEDIA ≥ 4.0 · BAJA < 4.0. "
                "Los porcentajes se calculan sobre el total de vulnerabilidades.",
                self.styles["Caption"],
            ))
        return elements

    def create_statistics_section(self):
        if self.stats["total_vulnerabilities"] == 0:
            return []
        elements = [PageBreak(),
                    Paragraph("DEPENDENCIAS MÁS VULNERABLES",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        vuln_by_lib = []
        for dep in self.dependencies:
            if dep.get("vulnerabilities"):
                vuln_by_lib.append({
                    "name": dep.get("fileName", "Unknown"),
                    "count": len(dep.get("vulnerabilities", [])),
                })
        vuln_by_lib.sort(key=lambda x: x["count"], reverse=True)
        top = vuln_by_lib[:15]
        if top:
            data = [["Librería", "Vulnerabilidades"]]
            for item in top:
                data.append([item["name"][:55], str(item["count"])])
            elements.append(styled_secondary_table(data, [4.0 * inch, 1.5 * inch]))
        return elements

    def _format_references(self, vuln):
        if not vuln.get("references"):
            return ""
        refs = []
        for r in vuln.get("references", [])[:2]:
            if isinstance(r, dict):
                if "name" in r:
                    refs.append(html.escape(str(r["name"])))
                elif "url" in r:
                    refs.append(html.escape(str(r["url"])))
            elif isinstance(r, str):
                refs.append(html.escape(str(r)))
        return f"<br/><b>Referencias:</b> {', '.join(refs)}" if refs else ""

    def _extract_vulns_by_severity(self):
        by_sev = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for dep in self.dependencies:
            for v in dep.get("vulnerabilities", []) or []:
                v["library"] = dep.get("fileName", "Unknown")
                by_sev[self.get_cvss_severity(self._get_vuln_cvss(v))].append(v)
        return by_sev

    def _create_severity_block(self, severity, vulns):
        elements = [PageBreak(),
                    Paragraph(f"VULNERABILIDADES · {severity} ({len(vulns)})",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        for idx, v in enumerate(vulns, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.1 * inch))
            cvss = self._get_vuln_cvss(v)
            vname = html.escape(str(v.get("name", "Sin nombre")))
            lib = html.escape(str(v.get("library", "N/A")))
            desc = html.escape(str(v.get("description") or "Sin descripción"))
            elements.append(Paragraph(f"<b>{idx}. {vname[:80]}</b>",
                                      self.styles["CustomHeading3"]))
            details = (
                f"<b>Librería:</b> {lib}<br/>"
                f"<b>CVE:</b> {vname}<br/>"
                f"<b>CVSS score:</b> {cvss}<br/>"
                f"<b>Descripción:</b> {desc[:250]}"
                f"{self._format_references(v)}"
            )
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
                        Paragraph("REPORTE DE ANÁLISIS DE DEPENDENCIAS",
                                  self.styles["CustomTitle"]),
                        Paragraph("OWASP Dependency-Check · SCA",
                                  self.styles["CustomSubtitle"]),
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
            print(f"✓ PDF OWASP generado exitosamente: {self.pdf_output_path}")
        except Exception as e:
            print(f"✗ Error al generar PDF OWASP: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 owasp_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)
    logo = sys.argv[3] if len(sys.argv) > 3 else None
    OWASPReportGenerator(sys.argv[1], sys.argv[2], logo).generate_pdf()


if __name__ == "__main__":
    main()
