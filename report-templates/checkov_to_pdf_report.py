#!/usr/bin/env python3
"""
Generador PDF institucional para reportes JSON de Checkov (IaC).
Uso: python3 checkov_to_pdf_report.py <json_report> <output_pdf> [logo_path]

Refactor: usa el branding común Template_SM_Ciber (branding_sm.py).
La lógica de parseo de Checkov permanece intacta; solo cambia la presentación.
"""

import html
import json
import os
import sys
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Branding común (Template_SM_Ciber)
from branding_sm import (
    BODY_TEXT,
    DARK,
    DOC_MARGINS,
    FONT_SANS,
    FONT_SANS_BOLD,
    GRAY_BORDER,
    GREEN_OK,
    RED,
    ROW_ALT,
    SEVERITY_COLORS,
    TEAL,
    build_styles,
    page_decorations_factory,
    tabla_distribucion_severidad,
)


class CheckovReportGenerator:
    # Constantes canónicas de severidades (español)
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte Checkov · IaC Security"
    CODIGO = "DevSecOps-CHECKOV"

    def __init__(self, json_report_path, pdf_output_path, logo_filename=None):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path

        # Permite override del logo desde CLI; si no, el módulo branding usa el default
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if logo_filename:
            # Compat: primero busca en el script dir (comportamiento heredado)
            candidate = os.path.join(script_dir, logo_filename)
            if os.path.exists(candidate):
                self.logo_path = candidate
            else:
                self.logo_path = logo_filename  # ruta absoluta o relativa cwd
        else:
            self.logo_path = None  # branding_sm elige el default

        self.test_type = self.CODIGO
        self.raw_data = None
        self.failed_checks = []
        self.stats = {}

        self.styles = build_styles()

    # ------------------------------------------------------------------
    # Callback onPage (delegado al branding común)
    # ------------------------------------------------------------------
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
                self.raw_data = json.load(f)

            if isinstance(self.raw_data, dict):
                self.raw_data = [self.raw_data]
            elif not isinstance(self.raw_data, list):
                self.raw_data = []

        except Exception as e:
            print(f"✗ Error al cargar JSON Checkov: {str(e)}")
            sys.exit(1)

    def _extract_severity(self, check):
        """
        Normaliza la severidad reportada por Checkov.

        Convención del equipo (ver sec-iac-terraform.yml consolidator):
        cuando Checkov open-source no trae `severity` (llega None), el
        hallazgo se clasifica como ALTA — la severidad la asigna Bridgecrew
        Prisma Cloud, no disponible en el pipeline gratuito.
        """
        sev = check.get("severity")
        if isinstance(sev, dict):
            sev = sev.get("value") or ""
        if not isinstance(sev, str) or not sev.strip():
            return self.SEV_ALTA  # fallback consistente con el consolidator

        sev = sev.upper()
        if "CRIT" in sev:
            return self.SEV_CRITICA
        if "HIGH" in sev:
            return self.SEV_ALTA
        if "MED" in sev:
            return self.SEV_MEDIA
        if "LOW" in sev:
            return self.SEV_BAJA
        return self.SEV_ALTA

    def calculate_statistics(self):
        total_passed = 0
        total_failed = 0
        sin_severity_nativa = 0
        frameworks_found = set()

        sev_counts = {
            self.SEV_CRITICA: 0,
            self.SEV_ALTA: 0,
            self.SEV_MEDIA: 0,
            self.SEV_BAJA: 0,
        }

        for report in self.raw_data:
            framework = report.get("check_type", "unknown")
            frameworks_found.add(framework)

            summary = report.get("summary", {})
            total_passed += summary.get("passed", 0)

            results = report.get("results", {})
            failed_list = results.get("failed_checks", [])

            for check in failed_list:
                check["framework"] = framework
                raw_sev = check.get("severity")
                if isinstance(raw_sev, dict):
                    raw_sev = raw_sev.get("value") or ""
                if not isinstance(raw_sev, str) or not raw_sev.strip():
                    sin_severity_nativa += 1
                severity = self._extract_severity(check)
                sev_counts[severity] += 1
                self.failed_checks.append(check)
                total_failed += 1

        self.stats = {
            "frameworks": list(frameworks_found),
            "total_passed": total_passed,
            "total_failed": total_failed,
            "total_checks": total_passed + total_failed,
            "critical": sev_counts[self.SEV_CRITICA],
            "high": sev_counts[self.SEV_ALTA],
            "medium": sev_counts[self.SEV_MEDIA],
            "low": sev_counts[self.SEV_BAJA],
            "sin_severity_nativa": sin_severity_nativa,
        }

    # ------------------------------------------------------------------
    # Secciones del PDF
    # ------------------------------------------------------------------
    def create_executive_summary(self):
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles["CustomHeading2"]))
        elements.append(Spacer(1, 0.15 * inch))

        fw_str = ", ".join(self.stats["frameworks"]) if self.stats["frameworks"] else "N/A"
        has_risk = self.stats["total_failed"] > 0

        if not has_risk:
            status_html = f"<font color='#26C130'><b>APROBADO</b></font>"
            status_desc = (
                "El análisis de Infraestructura como Código (IaC) concluyó "
                "exitosamente. No se detectaron configuraciones inseguras, "
                "cumpliendo con los estándares definidos para el despliegue."
            )
        else:
            status_html = f"<font color='#E31952'><b>FALLIDO</b></font>"
            status_desc = (
                "El análisis detectó configuraciones inseguras. Es obligatorio "
                "revisar y corregir estos hallazgos para evitar exposición de "
                "recursos, brechas de datos o incumplimiento normativo antes "
                "del despliegue."
            )

        summary_text = (
            f"<b>Estado del análisis:</b> {status_html}<br/>"
            f"{status_desc}<br/><br/>"
            f"<b>Frameworks analizados (IaC):</b> {fw_str}<br/>"
            f"<b>Total de evaluaciones (controles):</b> {self.stats['total_checks']}<br/>"
            f"<b>Controles aprobados:</b> <font color='#26C130'>{self.stats['total_passed']}</font><br/>"
            f"<b>Controles fallidos (inseguros):</b> <font color='#E31952'>{self.stats['total_failed']}</font>"
        )
        elements.append(Paragraph(summary_text, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        # Tabla estándar de distribución por severidad (branding común)
        elements.append(
            Paragraph("Distribución por severidad", self.styles["CustomHeading3"])
        )
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(
            tabla_distribucion_severidad(self.stats, total=self.stats["total_failed"])
        )
        elements.append(Spacer(1, 0.15 * inch))

        caption_text = (
            "Los porcentajes se calculan sobre el total de hallazgos fallidos. "
            "Solo se listan severidades con conteo mayor a cero."
        )
        sin_sev = self.stats.get("sin_severity_nativa", 0)
        if sin_sev > 0:
            caption_text += (
                f"<br/><b>Nota:</b> {sin_sev} de {self.stats['total_failed']} "
                "hallazgos no traen severidad nativa (Checkov open-source no la "
                "expone; solo Bridgecrew/Prisma Cloud). Por convención del "
                "equipo se clasifican como <b>ALTA</b>."
            )
        elements.append(Paragraph(caption_text, self.styles["Caption"]))

        return elements

    def _extract_findings_by_severity(self):
        vulns = {
            self.SEV_CRITICA: [],
            self.SEV_ALTA: [],
            self.SEV_MEDIA: [],
            self.SEV_BAJA: [],
        }
        for check in self.failed_checks:
            vulns[self._extract_severity(check)].append(check)
        return vulns

    def _create_severity_block(self, severity, checks):
        elements = []
        elements.append(PageBreak())
        elements.append(
            Paragraph(
                f"HALLAZGOS DE INFRAESTRUCTURA · {severity} ({len(checks)})",
                self.styles["CustomHeading2"],
            )
        )
        elements.append(Spacer(1, 0.15 * inch))

        for idx, check in enumerate(checks, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.12 * inch))

            check_id = html.escape(str(check.get("check_id", "N/A")))
            check_name = html.escape(str(check.get("check_name", "Sin descripción")))
            file_path = html.escape(str(check.get("file_path", "N/A")))
            resource = html.escape(str(check.get("resource", "N/A")))
            framework = html.escape(str(check.get("framework", "N/A")).upper())
            guideline = check.get("guideline")

            lines = check.get("file_line_range", [])
            lines_str = f"{lines[0]} - {lines[1]}" if len(lines) == 2 else "N/A"

            elements.append(
                Paragraph(
                    f"<b>{idx}. [{check_id}]</b> {check_name[:120]}",
                    self.styles["CustomHeading3"],
                )
            )

            details = (
                f"<b>Framework / tipo:</b> {framework}<br/>"
                f"<b>Archivo:</b> {file_path} (líneas: {lines_str})<br/>"
                f"<b>Recurso afectado:</b> {resource}<br/>"
            )
            if guideline:
                details += f"<b>Guía de remediación:</b> {html.escape(str(guideline))}<br/>"
            elements.append(Paragraph(details, self.styles["BodyJustified"]))

        return elements

    def create_findings_section(self):
        elements = []
        vulns_by_severity = self._extract_findings_by_severity()

        for severity in [self.SEV_CRITICA, self.SEV_ALTA, self.SEV_MEDIA, self.SEV_BAJA]:
            checks = vulns_by_severity[severity]
            if checks:
                elements.extend(self._create_severity_block(severity, checks))

        return elements

    # ------------------------------------------------------------------
    # Orquestación
    # ------------------------------------------------------------------
    def generate_pdf(self):
        try:
            self.load_json_report()
            self.calculate_statistics()

            doc = SimpleDocTemplate(
                self.pdf_output_path,
                pagesize=letter,
                title=self.REPORT_TITLE,
                **DOC_MARGINS,
            )

            elements = []

            # Portada
            elements.append(Spacer(1, 1.4 * inch))
            elements.append(Paragraph("REPORTE DE SEGURIDAD IaC", self.styles["CustomTitle"]))
            elements.append(
                Paragraph(
                    "Checkov · Análisis de Infraestructura como Código",
                    self.styles["CustomSubtitle"],
                )
            )
            elements.append(Spacer(1, 0.3 * inch))
            elements.append(
                Paragraph(
                    f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                    self.styles["Caption"],
                )
            )
            elements.append(Spacer(1, 0.4 * inch))

            elements.append(Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]))
            elements.append(Spacer(1, 0.15 * inch))
            for line in [
                "1. Resumen ejecutivo y distribución por severidad",
                "2. Desglose de hallazgos por severidad",
            ]:
                elements.append(Paragraph(line, self.styles["BodyJustified"]))

            elements.append(PageBreak())
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_findings_section())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF Checkov generado exitosamente: {self.pdf_output_path}")

        except Exception as e:
            print(f"✗ Error al generar PDF: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 checkov_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)

    json_report = sys.argv[1]
    output_pdf = sys.argv[2]
    logo = sys.argv[3] if len(sys.argv) > 3 else None

    generator = CheckovReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()


if __name__ == "__main__":
    main()
