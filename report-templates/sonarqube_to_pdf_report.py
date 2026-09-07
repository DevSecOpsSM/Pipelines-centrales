#!/usr/bin/env python3
"""
Generador PDF institucional a partir de la API de SonarQube.
Uso: python3 sonarqube_to_pdf_report.py <url> <token> <project_key> <output_pdf> [logo_path]

Refactor: usa el branding común Template_SM_Ciber (branding_sm.py).

Mapeo institucional de severidad SonarQube → tabla estándar:
    BLOCKER  → CRÍTICA
    CRITICAL → ALTA
    MAJOR    → MEDIA
    MINOR    → BAJA
    INFO     → BAJA
"""

import base64
import json
import os
import sys
import urllib.request
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


class SonarQubeReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte SonarQube · Calidad y SAST"
    CODIGO = "DevSecOps-SONAR"

    def __init__(self, sonar_url, sonar_token, project_key, pdf_output_path,
                 logo_filename=None):
        self.sonar_url = sonar_url.rstrip("/")
        self.sonar_token = sonar_token
        self.project_key = project_key
        self.pdf_output_path = pdf_output_path

        script_dir = os.path.dirname(os.path.abspath(__file__))
        if logo_filename:
            candidate = os.path.join(script_dir, logo_filename)
            self.logo_path = candidate if os.path.exists(candidate) else logo_filename
        else:
            self.logo_path = None

        self.metrics = {}
        self.issues = []
        self.stats = {}

        self.styles = build_styles()

    def _page_callback(self):
        return page_decorations_factory(
            report_title=self.REPORT_TITLE,
            codigo=self.CODIGO,
            logo_path=self.logo_path,
        )

    # ------------------------------------------------------------------
    # API SonarQube (intacta)
    # ------------------------------------------------------------------
    def _make_api_request(self, endpoint):
        url = f"{self.sonar_url}{endpoint}"
        auth = base64.b64encode(f"{self.sonar_token}:".encode("utf-8")).decode("utf-8")
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {auth}")
        try:
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as e:
            print(f"✗ Error API SonarQube ({endpoint}): {e}")
            return None

    def fetch_data(self):
        print(f"📡 Conectando a SonarQube en {self.sonar_url}...")
        metrics_keys = "alert_status,bugs,vulnerabilities,security_hotspots,code_smells,sqale_index"
        m_data = self._make_api_request(
            f"/api/measures/component?component={self.project_key}&metricKeys={metrics_keys}"
        )
        if m_data and "component" in m_data:
            for m in m_data["component"].get("measures", []):
                self.metrics[m["metric"]] = m.get("value", "0")

        print("📥 Descargando issues...")
        page_index, page_size = 1, 500
        while True:
            data = self._make_api_request(
                f"/api/issues/search?componentKeys={self.project_key}&resolved=false"
                f"&ps={page_size}&p={page_index}&s=SEVERITY&asc=false"
            )
            if not data or "issues" not in data:
                break
            batch = data["issues"]
            self.issues.extend(batch)
            if len(batch) < page_size:
                break
            page_index += 1

        print("📥 Descargando Security Hotspots...")
        page_index = 1
        while True:
            data = self._make_api_request(
                f"/api/hotspots/search?projectKey={self.project_key}"
                f"&status=TO_REVIEW&ps={page_size}&p={page_index}"
            )
            if not data or "hotspots" not in data:
                break
            for h in data["hotspots"]:
                self.issues.append({
                    "severity": (h.get("vulnerabilityProbability") or "UNKNOWN").upper(),
                    "type": "SECURITY_HOTSPOT",
                    "component": h.get("component", ""),
                    "message": h.get("message", "Revisión de seguridad requerida"),
                    "line": h.get("line", "N/A"),
                })
            if len(data["hotspots"]) < page_size:
                break
            page_index += 1
        print(f"✓ Datos recuperados: {len(self.issues)} issues/hotspots")

    # ------------------------------------------------------------------
    # Clasificación de severidad
    # ------------------------------------------------------------------
    def map_sonar_severity(self, raw):
        sev = (raw or "MINOR").upper()
        if sev == "BLOCKER":
            return self.SEV_CRITICA
        if sev in ("CRITICAL", "HIGH"):
            return self.SEV_ALTA
        if sev in ("MAJOR", "MEDIUM"):
            return self.SEV_MEDIA
        # MINOR, INFO, LOW y desconocidas → BAJA
        return self.SEV_BAJA

    def calculate_statistics(self):
        critical = high = medium = low = 0
        by_type = defaultdict(int)
        for it in self.issues:
            sev = self.map_sonar_severity(it.get("severity"))
            if sev == self.SEV_CRITICA:
                critical += 1
            elif sev == self.SEV_ALTA:
                high += 1
            elif sev == self.SEV_MEDIA:
                medium += 1
            else:
                low += 1
            by_type[it.get("type", "ISSUE")] += 1

        self.stats = {
            "total": len(self.issues),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "by_type": dict(by_type),
        }

    # ------------------------------------------------------------------
    # Secciones del PDF
    # ------------------------------------------------------------------
    def create_executive_summary(self):
        elements = [Paragraph("RESUMEN EJECUTIVO DE CALIDAD",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        alert_status = self.metrics.get("alert_status", "UNKNOWN")
        passed = alert_status == "OK"
        debt_mins = int(self.metrics.get("sqale_index", 0) or 0)
        debt_str = f"{debt_mins // 60}h {debt_mins % 60}min" if debt_mins > 0 else "0min"

        summary = (
            f"<b>Proyecto analizado:</b> {self.project_key}<br/>"
            f"<b>Estado del Quality Gate:</b> {status_html(passed)}<br/>"
            f"<b>Deuda técnica estimada:</b> {debt_str}<br/><br/>"
            f"<b>Métricas de salud del código:</b><br/>"
            f"• <b>Bugs:</b> {self.metrics.get('bugs', 0)}<br/>"
            f"• <b>Vulnerabilidades:</b> {self.metrics.get('vulnerabilities', 0)}<br/>"
            f"• <b>Security Hotspots:</b> {self.metrics.get('security_hotspots', 0)} "
            f"(revisiones pendientes)<br/>"
            f"• <b>Code Smells:</b> {self.metrics.get('code_smells', 0)}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if self.stats["total"] > 0:
            elements.append(Paragraph("Distribución de issues por severidad",
                                      self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(
                self.stats, total=self.stats["total"]))
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "Mapeo institucional: BLOCKER → CRÍTICA · CRITICAL → ALTA · "
                "MAJOR → MEDIA · MINOR/INFO → BAJA. Los porcentajes se calculan "
                "sobre el total de issues detectados (incluye security hotspots).",
                self.styles["Caption"],
            ))

        rec_paragraph = (
            "<b>⚠ Acción urgente:</b> el proyecto no aprobó el Quality Gate. Priorizar la "
            "corrección de vulnerabilidades y bugs antes del siguiente paso a producción."
            if not passed else
            "<b>Mantener calidad:</b> el proyecto cumple los estándares actuales. "
            "Se recomienda abordar los Code Smells para reducir la deuda técnica a "
            "largo plazo."
        )
        elements.append(Spacer(1, 0.25 * inch))
        elements.append(Paragraph("ACCIONES RECOMENDADAS", self.styles["CustomHeading2"]))
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(Paragraph(rec_paragraph, self.styles["BodyJustified"]))
        return elements

    def create_issues_section(self):
        if not self.issues:
            return []
        elements = [PageBreak(),
                    Paragraph("DETALLE DE HALLAZGOS PRIORITARIOS",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        # Ordenar por severidad institucional
        sev_order = {self.SEV_CRITICA: 0, self.SEV_ALTA: 1, self.SEV_MEDIA: 2, self.SEV_BAJA: 3}
        sorted_issues = sorted(
            self.issues,
            key=lambda it: sev_order.get(self.map_sonar_severity(it.get("severity")), 99),
        )

        for idx, issue in enumerate(sorted_issues, 1):
            sev_inst = self.map_sonar_severity(issue.get("severity"))
            sev_native = issue.get("severity", "UNKNOWN")
            type_issue = issue.get("type", "ISSUE")
            component = str(issue.get("component", "")).split(":")[-1]
            msg = str(issue.get("message", "Sin descripción"))

            elements.append(Paragraph(
                f"<b>{idx}. [{sev_inst}] {type_issue}</b>",
                self.styles["CustomHeading3"],
            ))
            details = (
                f"<b>Archivo:</b> {component}<br/>"
                f"<b>Línea:</b> {issue.get('line', 'N/A')}<br/>"
                f"<b>Severidad nativa Sonar:</b> {sev_native}<br/>"
                f"<b>Mensaje:</b> {msg}"
            )
            elements.append(Paragraph(details, self.styles["BodyJustified"]))
            elements.append(Spacer(1, 0.1 * inch))
        return elements

    def create_type_breakdown_section(self):
        if not self.stats.get("by_type"):
            return []
        elements = [PageBreak(),
                    Paragraph("DISTRIBUCIÓN POR TIPO DE HALLAZGO",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        data = [["Tipo de hallazgo", "Cantidad"]]
        for t, cnt in sorted(self.stats["by_type"].items(), key=lambda x: x[1], reverse=True):
            data.append([str(t), str(cnt)])
        elements.append(styled_secondary_table(data, [3.5 * inch, 1.5 * inch]))
        return elements

    def generate_pdf(self):
        try:
            self.fetch_data()
            self.calculate_statistics()

            doc = SimpleDocTemplate(
                self.pdf_output_path, pagesize=letter,
                title=f"Reporte SonarQube · {self.project_key}", **DOC_MARGINS,
            )
            elements = [Spacer(1, 1.4 * inch),
                        Paragraph("REPORTE DE CALIDAD Y SEGURIDAD",
                                  self.styles["CustomTitle"]),
                        Paragraph(f"SonarQube · {self.project_key}",
                                  self.styles["CustomSubtitle"]),
                        Spacer(1, 0.3 * inch),
                        Paragraph(f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                                  self.styles["Caption"]),
                        Spacer(1, 0.4 * inch),
                        Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                        Spacer(1, 0.15 * inch)]
            for line in ["1. Resumen ejecutivo y distribución por severidad",
                         "2. Detalle de hallazgos prioritarios",
                         "3. Distribución por tipo de hallazgo"]:
                elements.append(Paragraph(line, self.styles["BodyJustified"]))
            elements.append(PageBreak())
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_issues_section())
            elements.extend(self.create_type_breakdown_section())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF SonarQube generado exitosamente: {self.pdf_output_path}")
        except Exception as e:
            print(f"✗ Error al generar PDF SonarQube: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 5:
        print("Uso: python3 sonarqube_to_pdf_report.py <url> <token> <project_key> "
              "<output_pdf> [logo_path]")
        sys.exit(1)
    logo = sys.argv[5] if len(sys.argv) > 5 else None
    SonarQubeReportGenerator(
        sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], logo
    ).generate_pdf()


if __name__ == "__main__":
    main()
