#!/usr/bin/env python3
"""
Generador PDF institucional para reportes JSON de Gitleaks (secretos).
Uso: python3 gitleaks_to_pdf_report.py <json_report> <output_pdf> [logo_path]

Refactor: usa el branding común Template_SM_Ciber (branding_sm.py).

Mapeo institucional de severidad:
    Secreto ACTIVO en código  → CRÍTICA
    Secreto GHOST (histórico) → BAJA (retirado del código vigente)
"""

import html
import json
import os
import sys
import textwrap
from collections import defaultdict
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer,
)
from reportlab.lib import colors

from branding_sm import (
    DOC_MARGINS,
    RED,
    ROW_ALT,
    build_styles,
    page_decorations_factory,
    status_html,
    styled_secondary_table,
    tabla_distribucion_severidad,
)


class GitleaksReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte Gitleaks · Secrets"
    CODIGO = "DevSecOps-GITLEAKS"

    def __init__(self, json_report_path, pdf_output_path, logo_filename=None):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path

        script_dir = os.path.dirname(os.path.abspath(__file__))
        if logo_filename:
            candidate = os.path.join(script_dir, logo_filename)
            self.logo_path = candidate if os.path.exists(candidate) else logo_filename
        else:
            self.logo_path = None

        self.secrets = []
        self.active_count = 0
        self.ghost_count = 0
        self.stats = {}

        self.styles = build_styles()
        # Estilo específico para el bloque de secreto expuesto
        self.styles.add(ParagraphStyle(
            name="SecretBox",
            parent=self.styles["BodyJustified"],
            fontSize=8.5,
            leading=11,
            textColor=RED,
            fontName="Courier-Bold",
            backColor=ROW_ALT,
            borderPadding=6,
            borderColor=colors.HexColor("#E31952"),
            borderWidth=0.5,
        ))

    def _page_callback(self):
        return page_decorations_factory(
            report_title=self.REPORT_TITLE,
            codigo=self.CODIGO,
            logo_path=self.logo_path,
        )

    def load_json_report(self):
        try:
            with open(self.json_report_path, "r", encoding="utf-8") as f:
                data = f.read()
            self.secrets = json.loads(data) if data.strip() else []

            workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

            for secret in self.secrets:
                file_path = secret.get("File", "")
                match_str = secret.get("Match", "")
                target_file = os.path.join(workspace_root, file_path)
                is_ghost = True
                if os.path.exists(target_file):
                    try:
                        with open(target_file, "r", encoding="utf-8", errors="ignore") as current:
                            if match_str in current.read():
                                is_ghost = False
                    except Exception:
                        pass
                secret["IsGhost"] = is_ghost
                if is_ghost:
                    self.ghost_count += 1
                else:
                    self.active_count += 1

            print(
                f"✓ Reporte Gitleaks cargado: {len(self.secrets)} secretos totales "
                f"({self.active_count} Activos, {self.ghost_count} Históricos/Ghost)"
            )
        except FileNotFoundError:
            print(f"✗ Archivo {self.json_report_path} no encontrado.")
            sys.exit(1)
        except json.JSONDecodeError:
            print("✗ JSON de Gitleaks corrupto.")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Error inesperado al leer JSON: {str(e)}")
            sys.exit(1)

    def calculate_statistics(self):
        rule_counts = defaultdict(int)
        file_counts = defaultdict(int)
        for secret in self.secrets:
            rule_counts[secret.get("Description", "Regla desconocida")] += 1
            file_counts[secret.get("File", "Archivo desconocido")] += 1

        # Para la tabla estándar de severidad: Activos → CRÍTICA, Ghost → BAJA
        self.stats = {
            "total": len(self.secrets),
            "active": self.active_count,
            "ghost": self.ghost_count,
            "critical": self.active_count,
            "high": 0,
            "medium": 0,
            "low": self.ghost_count,
            "by_rule": dict(sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)),
            "by_file": dict(sorted(file_counts.items(), key=lambda x: x[1], reverse=True)),
            "files_affected": len(file_counts),
        }

    def create_executive_summary(self):
        elements = [Paragraph("RESUMEN EJECUTIVO", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        total = self.stats["total"]
        active = self.stats["active"]
        # Solo se aprueba si no hay secretos activos
        passed = active == 0

        if total == 0:
            desc = ("El escaneo de seguridad en busca de secretos expuestos concluyó "
                    "exitosamente. No se detectaron credenciales, tokens, llaves ni "
                    "contraseñas hardcodeadas. El proyecto cumple con la política de "
                    "cero secretos en el repositorio.")
        elif passed:
            desc = (f"No hay secretos ACTIVOS en el código vigente. Los {self.ghost_count} "
                    "hallazgos corresponden a Ghost Leaks (persisten solo en el historial "
                    "de Git). Cubiertos por el acuerdo de ghost leaks del equipo.")
        else:
            desc = ("Se detectaron secretos ACTIVOS en el código vigente. La exposición "
                    "de secretos es una de las vulnerabilidades más críticas: cualquier "
                    "actor con acceso al repositorio podría extraerlos y comprometer "
                    "infraestructura, bases de datos o servicios en la nube.")

        summary = (
            f"<b>Estado del análisis:</b> {status_html(passed)}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Total de secretos detectados:</b> {total}<br/>"
            f"<b>Activos en código vigente:</b> {active}<br/>"
            f"<b>Históricos (Ghost Leaks):</b> {self.ghost_count}<br/>"
            f"<b>Archivos comprometidos:</b> {self.stats['files_affected']}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if total > 0:
            elements.append(Paragraph("Distribución por severidad",
                                      self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(self.stats, total=total))
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "Mapeo institucional: secreto ACTIVO en código → CRÍTICA · "
                "secreto GHOST (histórico, retirado del código vigente) → BAJA. "
                "Los Ghost Leaks requieren acceso al historial de Git privado para "
                "explotarse.",
                self.styles["Caption"],
            ))

        if active > 0:
            elements.append(Spacer(1, 0.25 * inch))
            elements.append(Paragraph("PLAN DE REMEDIACIÓN INMEDIATA",
                                      self.styles["CustomHeading2"]))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph(
                "<b>1. Revocación obligatoria:</b> considerar todas las credenciales "
                "listadas como comprometidas y revocarlas en su origen (AWS, DB, APIs "
                "de terceros) de manera inmediata.<br/>"
                "<b>2. Limpieza de historial:</b> eliminar el secreto del commit actual "
                "no es suficiente. Usar <font face='Courier'>git filter-repo</font> "
                "para purgar la credencial de todo el historial de Git.<br/>"
                "<b>3. Inyección segura:</b> implementar el uso de variables de "
                "entorno, Azure Key Vault o AWS Secrets Manager para inyectar estos "
                "valores en tiempo de despliegue.",
                self.styles["BodyJustified"],
            ))
        return elements

    def create_statistics_section(self):
        if self.stats["total"] == 0:
            return []
        elements = [PageBreak(),
                    Paragraph("TIPOS DE SECRETOS DETECTADOS",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        data = [["Tipo de secreto / regla", "Cantidad", "% del total"]]
        for rule, cnt in list(self.stats["by_rule"].items())[:15]:
            pct = (cnt / self.stats["total"] * 100) if self.stats["total"] > 0 else 0
            data.append([rule[:60], str(cnt), f"{pct:.1f} %"])
        elements.append(styled_secondary_table(data, [3.5 * inch, 1.0 * inch, 1.2 * inch]))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("ARCHIVOS MÁS COMPROMETIDOS", self.styles["CustomHeading3"]))
        elements.append(Spacer(1, 0.1 * inch))
        data = [["Ruta del archivo", "Secretos"]]
        for f, cnt in list(self.stats["by_file"].items())[:15]:
            data.append([f[:70], str(cnt)])
        elements.append(styled_secondary_table(data, [4.5 * inch, 1.0 * inch]))
        return elements

    def create_findings_section(self):
        if self.stats["total"] == 0:
            return []
        elements = [PageBreak(),
                    Paragraph(f"DETALLE DE HALLAZGOS ({self.stats['total']})",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        # Ordenar: primero activos, luego ghost
        sorted_secrets = sorted(self.secrets, key=lambda s: s.get("IsGhost", True))

        for idx, secret in enumerate(sorted_secrets, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.15 * inch))
            rule = html.escape(str(secret.get("Description", "Regla desconocida")))
            file_path = html.escape(str(secret.get("File", "Archivo desconocido")))
            line = str(secret.get("StartLine", "N/A"))
            raw_author = (secret.get("Author") or "").strip()
            author = html.escape(raw_author) if raw_author else "No disponible (--no-git)"
            raw_commit = (secret.get("Commit") or "").strip()
            commit = html.escape(raw_commit[:8]) if raw_commit else "N/A"
            is_ghost = secret.get("IsGhost", False)

            if is_ghost:
                badge = "<font color='#26C130'><i>[Histórico · Ghost Leak]</i></font>"
            else:
                badge = "<font color='#E31952'><b>[Activo en código]</b></font>"

            elements.append(Paragraph(
                f"<b>{idx}. {rule}</b> {badge}",
                self.styles["CustomHeading3"],
            ))
            details = (
                f"<b>Archivo:</b> {file_path}<br/>"
                f"<b>Línea:</b> {line} · <b>Commit:</b> {commit} · <b>Autor:</b> {author}"
            )
            elements.append(Paragraph(details, self.styles["BodyJustified"]))
            elements.append(Spacer(1, 0.05 * inch))

            raw_match = str(secret.get("Match", "No se pudo extraer el string"))
            safe_match = raw_match.replace("<", "&lt;").replace(">", "&gt;")
            wrapped = textwrap.fill(safe_match, width=80, break_long_words=True,
                                    break_on_hyphens=True)
            elements.append(Paragraph("<b>Fragmento expuesto:</b>",
                                      self.styles["BodyJustified"]))
            elements.append(Preformatted(wrapped, self.styles["SecretBox"]))
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
                        Paragraph("REPORTE DE DETECCIÓN DE SECRETOS",
                                  self.styles["CustomTitle"]),
                        Paragraph("Gitleaks · Análisis estático de credenciales",
                                  self.styles["CustomSubtitle"]),
                        Spacer(1, 0.3 * inch),
                        Paragraph(f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                                  self.styles["Caption"]),
                        Spacer(1, 0.4 * inch),
                        Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                        Spacer(1, 0.15 * inch)]
            for line in ["1. Resumen ejecutivo, distribución y remediación",
                         "2. Tipos de secretos y archivos comprometidos",
                         "3. Detalle de hallazgos (activos y ghost)"]:
                elements.append(Paragraph(line, self.styles["BodyJustified"]))
            elements.append(PageBreak())
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF Gitleaks generado exitosamente: {self.pdf_output_path}")
        except Exception as e:
            print(f"✗ Error al generar PDF Gitleaks: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 gitleaks_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)
    logo = sys.argv[3] if len(sys.argv) > 3 else None
    GitleaksReportGenerator(sys.argv[1], sys.argv[2], logo).generate_pdf()


if __name__ == "__main__":
    main()
