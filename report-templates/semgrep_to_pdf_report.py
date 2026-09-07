#!/usr/bin/env python3
"""
Generador PDF institucional para reportes JSON de Semgrep (SAST).
Uso: python3 semgrep_to_pdf_report.py <json_report> <output_pdf> [logo_path]

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


class SemgrepReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte Semgrep · SAST"
    CODIGO = "DevSecOps-SEMGREP"

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
        self.errors = []
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
            self.results = self.data.get("results", [])
            self.errors = self.data.get("errors", [])
            print("✓ Reporte Semgrep cargado exitosamente.")
        except Exception as e:
            print(f"✗ Error al cargar JSON Semgrep: {str(e)}")
            sys.exit(1)

    def map_semgrep_severity(self, raw_severity, confidence=""):
        """
        Mapeo Semgrep → institucional:
            ERROR + confidence HIGH → CRÍTICA
            ERROR                   → ALTA
            WARNING                 → MEDIA
            INFO                    → BAJA
        """
        sev = (raw_severity or "INFO").upper()
        conf = (confidence or "").upper()
        if sev == "ERROR":
            return self.SEV_CRITICA if conf == "HIGH" else self.SEV_ALTA
        if sev == "WARNING":
            return self.SEV_MEDIA
        return self.SEV_BAJA

    def _severity_of(self, result):
        extra = result.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        return self.map_semgrep_severity(extra.get("severity"), meta.get("confidence"))

    def calculate_statistics(self):
        critical = high = medium = low = 0
        finding_by_rule = defaultdict(int)
        owasp_categories = defaultdict(int)

        for r in self.results:
            sev = self._severity_of(r)
            if sev == self.SEV_CRITICA:
                critical += 1
            elif sev == self.SEV_ALTA:
                high += 1
            elif sev == self.SEV_MEDIA:
                medium += 1
            else:
                low += 1

            check_id = r.get("check_id", "unknown")
            rule_short = check_id.split(".")[-1] if "." in check_id else check_id
            finding_by_rule[rule_short] += 1

            meta = (r.get("extra", {}) or {}).get("metadata", {}) or {}
            owasp = meta.get("owasp")
            if isinstance(owasp, list):
                for o in owasp:
                    owasp_categories[str(o)[:50]] += 1
            elif isinstance(owasp, str):
                owasp_categories[owasp[:50]] += 1

        self.stats = {
            "total_findings": len(self.results),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "errors_semgrep": len(self.errors),
            "top_rules": dict(sorted(finding_by_rule.items(), key=lambda x: x[1], reverse=True)),
            "owasp_categories": dict(sorted(owasp_categories.items(), key=lambda x: x[1], reverse=True)),
        }

    def create_executive_summary(self):
        elements = [Paragraph("RESUMEN EJECUTIVO", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        total = self.stats["total_findings"]
        passed = total == 0

        if passed:
            desc = ("El análisis SAST de Semgrep no detectó patrones de código "
                    "inseguros contra las reglas OWASP Top 10, secrets y CI. "
                    "El código cumple con los estándares de seguridad definidos.")
        else:
            desc = ("Semgrep detectó patrones de código que violan controles OWASP "
                    "Top 10 y/o buenas prácticas de seguridad. Es obligatorio "
                    "revisar y corregir los hallazgos antes del despliegue.")

        summary = (
            f"<b>Estado del análisis:</b> {status_html(passed)}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Reglas aplicadas:</b> p/owasp-top-ten · p/secrets · p/ci<br/>"
            f"<b>Total de hallazgos:</b> {total}<br/>"
            f"<b>Advertencias del motor:</b> {self.stats['errors_semgrep']}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if total > 0:
            elements.append(Paragraph("Distribución por severidad", self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(self.stats, total=total))
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "Mapeo: ERROR + confidence HIGH → CRÍTICA · ERROR → ALTA · "
                "WARNING → MEDIA · INFO → BAJA. Los porcentajes se calculan "
                "sobre el total de hallazgos.",
                self.styles["Caption"],
            ))
        return elements

    def create_statistics_section(self):
        if self.stats["total_findings"] == 0:
            return []
        elements = [PageBreak(),
                    Paragraph("REGLAS SEMGREP MÁS DISPARADAS",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        top_rules = list(self.stats["top_rules"].items())[:15]
        if top_rules:
            data = [["Regla", "Ocurrencias"]]
            for rule, cnt in top_rules:
                data.append([rule[:60], str(cnt)])
            elements.append(styled_secondary_table(data, [4.0 * inch, 1.5 * inch]))
            elements.append(Spacer(1, 0.3 * inch))

        owasp_list = list(self.stats["owasp_categories"].items())[:10]
        if owasp_list:
            elements.append(Paragraph("CATEGORÍAS OWASP TOP 10 DETECTADAS",
                                      self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.1 * inch))
            data = [["Categoría OWASP", "Hallazgos"]]
            for cat, cnt in owasp_list:
                data.append([cat, str(cnt)])
            elements.append(styled_secondary_table(data, [4.0 * inch, 1.5 * inch]))
        return elements

    def _extract_findings_by_severity(self):
        by_sev = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for r in self.results:
            by_sev[self._severity_of(r)].append(r)
        return by_sev

    def _create_severity_block(self, severity, findings):
        elements = [PageBreak(),
                    Paragraph(f"HALLAZGOS SAST · {severity} ({len(findings)})",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        for idx, r in enumerate(findings, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.1 * inch))
            check_id = html.escape(str(r.get("check_id", "?")))
            rule_short = check_id.split(".")[-1] if "." in check_id else check_id
            path = html.escape(str(r.get("path", "?")))
            start = r.get("start", {}).get("line", "?")
            end = r.get("end", {}).get("line", start)
            line_str = f"{start}" if start == end else f"{start}-{end}"

            extra = r.get("extra", {}) or {}
            message = html.escape(str(extra.get("message", ""))[:300])
            fix = extra.get("fix")
            meta = extra.get("metadata", {}) or {}

            elements.append(Paragraph(
                f"<b>{idx}. [{html.escape(rule_short)}]</b>",
                self.styles["CustomHeading3"],
            ))
            details = (
                f"<b>Archivo:</b> {path} (línea {line_str})<br/>"
                f"<b>Regla completa:</b> {check_id}<br/>"
                f"<b>Descripción:</b> {message}"
            )
            owasp = meta.get("owasp")
            if owasp:
                owasp_str = owasp[0] if isinstance(owasp, list) else str(owasp)
                details += f"<br/><b>OWASP:</b> {html.escape(str(owasp_str)[:90])}"
            cwe = meta.get("cwe")
            if cwe:
                cwe_str = cwe[0] if isinstance(cwe, list) else str(cwe)
                details += f"<br/><b>CWE:</b> {html.escape(str(cwe_str)[:70])}"
            if fix:
                details += f"<br/><b>Sugerencia de fix:</b> {html.escape(str(fix)[:200])}"
            references = meta.get("references") or []
            if references and isinstance(references, list):
                details += f"<br/><b>Referencia:</b> {html.escape(str(references[0])[:100])}"

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
                        Paragraph("REPORTE DE SEGURIDAD SAST", self.styles["CustomTitle"]),
                        Paragraph("Semgrep · OWASP Top 10 + Secrets + CI",
                                  self.styles["CustomSubtitle"]),
                        Spacer(1, 0.3 * inch),
                        Paragraph(f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                                  self.styles["Caption"]),
                        Spacer(1, 0.4 * inch),
                        Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                        Spacer(1, 0.15 * inch)]
            for line in ["1. Resumen ejecutivo y distribución por severidad",
                         "2. Reglas y categorías OWASP más frecuentes",
                         "3. Desglose de hallazgos por severidad"]:
                elements.append(Paragraph(line, self.styles["BodyJustified"]))
            elements.append(PageBreak())
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF Semgrep generado exitosamente: {self.pdf_output_path}")
        except Exception as e:
            print(f"✗ Error al generar PDF Semgrep: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 semgrep_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)
    logo = sys.argv[3] if len(sys.argv) > 3 else None
    SemgrepReportGenerator(sys.argv[1], sys.argv[2], logo).generate_pdf()


if __name__ == "__main__":
    main()
