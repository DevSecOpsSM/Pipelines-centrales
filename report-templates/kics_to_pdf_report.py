#!/usr/bin/env python3
"""
Generador PDF institucional para reportes JSON de KICS (IaC multi-format).
Uso: python3 kics_to_pdf_report.py <json_report> <output_pdf> [logo_path]

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
from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer

from branding_sm import (
    DOC_MARGINS,
    build_styles,
    page_decorations_factory,
    status_html,
    styled_secondary_table,
    tabla_distribucion_severidad,
)


class KICSReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte KICS · IaC Multi-format"
    CODIGO = "DevSecOps-KICS"

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
        self.vulnerabilities = []
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

            self.vulnerabilities = []
            for query in self.data.get("queries", []):
                for file_info in query.get("files", []):
                    self.vulnerabilities.append({
                        "queryName": query.get("query_name", "Sin título"),
                        "severity": (query.get("severity") or "UNKNOWN").upper(),
                        "category": query.get("category", "Uncategorized"),
                        "platform": query.get("platform", "Unknown"),
                        "description": query.get("description", "Sin descripción"),
                        "file": file_info.get("file_name", "Archivo desconocido"),
                        "line": file_info.get("line", "N/A"),
                        "value": file_info.get("actual_value", ""),
                    })
            print(f"✓ Reporte KICS cargado: {len(self.vulnerabilities)} hallazgos")
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            sys.exit(1)

    def map_kics_severity(self, raw):
        """
        KICS expone CRITICAL/HIGH/MEDIUM/LOW/INFO. Institucional solo maneja
        4 niveles: INFO se agrega a BAJA para mantener la tabla estándar.
        """
        sev = (raw or "UNKNOWN").upper()
        if sev == "CRITICAL":
            return self.SEV_CRITICA
        if sev == "HIGH":
            return self.SEV_ALTA
        if sev == "MEDIUM":
            return self.SEV_MEDIA
        # LOW e INFO se agrupan como BAJA (INFO no bloquea)
        return self.SEV_BAJA

    def calculate_statistics(self):
        critical = high = medium = low = 0
        info_native = 0
        category_counts = defaultdict(int)
        platform_counts = defaultdict(int)

        for v in self.vulnerabilities:
            sev = self.map_kics_severity(v["severity"])
            if v["severity"] == "INFO":
                info_native += 1
            if sev == self.SEV_CRITICA:
                critical += 1
            elif sev == self.SEV_ALTA:
                high += 1
            elif sev == self.SEV_MEDIA:
                medium += 1
            else:
                low += 1
            category_counts[v["category"]] += 1
            platform_counts[v["platform"]] += 1

        self.stats = {
            "total": len(self.vulnerabilities),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info_native": info_native,
            "by_category": dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)),
            "by_platform": dict(platform_counts),
        }

    def create_executive_summary(self):
        elements = [Paragraph("RESUMEN EJECUTIVO", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        total = self.stats["total"]
        passed = total == 0

        if passed:
            desc = ("La validación de configuraciones (KICS) se ejecutó sin detectar "
                    "hallazgos. Los archivos IaC cumplen las mejores prácticas de "
                    "seguridad en la nube.")
        else:
            desc = ("Se identificaron brechas o avisos de configuración. Desplegar bajo "
                    "estas condiciones expone el entorno a configuraciones por defecto "
                    "inseguras o falta de controles de acceso.")

        platforms = ", ".join(self.stats["by_platform"].keys()) or "N/A"
        summary = (
            f"<b>Estado del análisis:</b> {status_html(passed)}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Plataformas analizadas:</b> {platforms}<br/>"
            f"<b>Total de hallazgos:</b> {total}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if total > 0:
            elements.append(Paragraph("Distribución por severidad", self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(self.stats, total=total))
            elements.append(Spacer(1, 0.15 * inch))
            caption = ("Severidad reportada nativamente por KICS. Los hallazgos INFO se "
                       "agrupan en BAJA para la tabla institucional.")
            if self.stats["info_native"] > 0:
                caption += (f" <b>Nota:</b> {self.stats['info_native']} de {total} "
                            "hallazgos son INFO nativo (no bloqueantes).")
            elements.append(Paragraph(caption, self.styles["Caption"]))
        return elements

    def create_statistics_section(self):
        if self.stats["total"] == 0:
            return []
        elements = [PageBreak(),
                    Paragraph("PRINCIPALES CATEGORÍAS DE HALLAZGOS",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        top_cats = list(self.stats["by_category"].items())[:10]
        if top_cats:
            data = [["Categoría", "Cantidad"]]
            for cat, cnt in top_cats:
                data.append([cat[:55], str(cnt)])
            elements.append(styled_secondary_table(data, [4.0 * inch, 1.5 * inch]))
        return elements

    def create_findings_section(self):
        elements = []
        by_sev = defaultdict(list)
        for v in self.vulnerabilities:
            by_sev[self.map_kics_severity(v["severity"])].append(v)

        for severity in [self.SEV_CRITICA, self.SEV_ALTA, self.SEV_MEDIA, self.SEV_BAJA]:
            vulns = by_sev[severity]
            if not vulns:
                continue
            elements.append(PageBreak())
            elements.append(Paragraph(f"HALLAZGOS · {severity} ({len(vulns)})",
                                      self.styles["CustomHeading2"]))
            elements.append(Spacer(1, 0.15 * inch))
            for idx, v in enumerate(vulns, 1):
                if idx > 1:
                    elements.append(Spacer(1, 0.1 * inch))
                elements.append(Paragraph(
                    f"<b>{idx}. {html.escape(str(v.get('queryName', 'Sin título'))[:120])}</b>",
                    self.styles["CustomHeading3"],
                ))
                details = (
                    f"<b>Archivo:</b> {html.escape(str(v.get('file', '?')))}<br/>"
                    f"<b>Línea:</b> {html.escape(str(v.get('line', 'N/A')))}<br/>"
                    f"<b>Categoría:</b> {html.escape(str(v.get('category', 'N/A')))}<br/>"
                    f"<b>Descripción:</b> {html.escape(str(v.get('description', ''))[:250])}"
                )
                elements.append(Paragraph(details, self.styles["BodyJustified"]))
                value = v.get("value", "")
                if value:
                    elements.append(Spacer(1, 0.05 * inch))
                    elements.append(Paragraph("<b>Fragmento de configuración:</b>",
                                              self.styles["BodyJustified"]))
                    elements.append(Preformatted(str(value)[:280], self.styles["Mono"]))
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
                        Paragraph("REPORTE DE ANÁLISIS DE CONFIGURACIÓN",
                                  self.styles["CustomTitle"]),
                        Paragraph("KICS · IaC Multi-format Security Scanner",
                                  self.styles["CustomSubtitle"]),
                        Spacer(1, 0.3 * inch),
                        Paragraph(f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                                  self.styles["Caption"]),
                        Spacer(1, 0.4 * inch),
                        Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                        Spacer(1, 0.15 * inch)]
            for line in ["1. Resumen ejecutivo y distribución por severidad",
                         "2. Categorías principales de hallazgos",
                         "3. Desglose de hallazgos por severidad"]:
                elements.append(Paragraph(line, self.styles["BodyJustified"]))
            elements.append(PageBreak())
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF KICS generado exitosamente: {self.pdf_output_path}")
        except Exception as e:
            print(f"✗ Error al generar PDF KICS: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 kics_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)
    logo = sys.argv[3] if len(sys.argv) > 3 else None
    KICSReportGenerator(sys.argv[1], sys.argv[2], logo).generate_pdf()


if __name__ == "__main__":
    main()
