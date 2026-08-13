#!/usr/bin/env python3
"""
Script para convertir el análisis full de Terraform (fmt + validate + tflint +
Checkov) a un ÚNICO PDF estructurado institucional.

Uso:
  python3 terraform_full_to_pdf_report.py <primary_json> <output_pdf> [logo_path]

  <primary_json> debe apuntar a checkov-raw.json. El generator busca los otros
  2 JSONs en el mismo directorio:
    - terraform-native-raw.json  (fmt + validate)
    - tflint-raw.json

  Los JSONs ausentes se saltan silenciosamente (la sección correspondiente
  no se renderiza).
"""

import html
import json
import os
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)


class TerraformFullReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA    = "ALTA"
    SEV_MEDIA   = "MEDIA"
    SEV_BAJA    = "BAJA"
    SEV_INFO    = "INFO"

    SEV_ORDER = [SEV_CRITICA, SEV_ALTA, SEV_MEDIA, SEV_BAJA, SEV_INFO]

    def __init__(self, primary_json_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.primary_json_path = primary_json_path
        self.pdf_output_path   = pdf_output_path
        self.input_dir         = os.path.dirname(os.path.abspath(primary_json_path))

        script_dir = os.path.dirname(os.path.abspath(__file__))
        # logo_filename puede ser absoluto (resuelto por resolve_logo_path del batch)
        self.logo_path = logo_filename if os.path.isabs(logo_filename) else os.path.join(script_dir, logo_filename)

        self.test_type = "DevSecOps-TERRAFORM-FULL"

        self.native  = {}
        self.tflint  = []
        self.checkov = []

        self.stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.tools_present = []

        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='CustomTitle', parent=self.styles['Heading1'],
            fontSize=24, textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30, alignment=TA_CENTER, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='CustomHeading2', parent=self.styles['Heading2'],
            fontSize=14, textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12, spaceBefore=12, fontName='Helvetica-Bold',
            borderColor=colors.HexColor('#00e5bd'), borderWidth=2,
            borderPadding=8, borderRadius=3,
        ))
        self.styles.add(ParagraphStyle(
            name='BodyJustified', parent=self.styles['BodyText'],
            alignment=TA_JUSTIFY, fontSize=10, leading=13,
            textColor=colors.HexColor('#2c3e50'),
        ))

    def draw_header(self, canvas, doc):
        canvas.saveState()
        width, height = letter
        if os.path.exists(self.logo_path):
            try:
                canvas.drawImage(self.logo_path, 40, height - 70,
                                 width=140, height=40, preserveAspectRatio=True, mask='auto')
            except Exception as exc:
                print(f"[WARN] Logo no cargable ({exc})", file=sys.stderr)

        meta = [
            ['Código:', self.test_type],
            ['Vigente desde:', datetime.now().strftime('%d/%m/%Y')],
            ['Clasificación:', 'Confidencial'],
        ]
        t = Table(meta, colWidths=[80, 100])
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

    def _load_json(self, filename):
        path = os.path.join(self.input_dir, filename)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding='utf-8') as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] No se pudo leer {path}: {exc}", file=sys.stderr)
            return None

    def load_all(self):
        native = self._load_json("terraform-native-raw.json")
        if native is not None:
            self.native = native
            self.tools_present.append("terraform fmt + validate")

        tflint_raw = self._load_json("tflint-raw.json")
        if tflint_raw is not None:
            entries = tflint_raw if isinstance(tflint_raw, list) else [tflint_raw]
            for entry in entries:
                d = entry.get("_dir", "?")
                for it in entry.get("issues", []) or []:
                    it["_dir"] = d
                    self.tflint.append(it)
            self.tools_present.append("tflint")

        checkov_raw = self._load_json(os.path.basename(self.primary_json_path))
        if checkov_raw is not None:
            reports = checkov_raw if isinstance(checkov_raw, list) else [checkov_raw]
            for rep in reports:
                self.checkov.extend((rep.get("results") or {}).get("failed_checks", []) or [])
            self.tools_present.append("Checkov")

    def calculate_stats(self):
        # terraform-native
        if self.native:
            unformatted = self.native.get("fmt", {}).get("unformatted_files", []) or []
            self.stats["info"] += len(unformatted)
            for entry in self.native.get("validate", {}).get("by_dir", []) or []:
                for diag in entry.get("diagnostics", []) or []:
                    sev = (diag.get("severity") or "info").lower()
                    if sev == "error":
                        self.stats["critical"] += 1
                    elif sev == "warning":
                        self.stats["low"] += 1
                    else:
                        self.stats["info"] += 1

        # tflint
        for it in self.tflint:
            sev = (it.get("rule", {}).get("severity") or "notice").lower()
            if sev == "error":
                self.stats["medium"] += 1
            elif sev == "warning":
                self.stats["low"] += 1
            else:
                self.stats["info"] += 1

        # Checkov
        for c in self.checkov:
            sev = (c.get("severity") or "HIGH").upper()
            if sev == "CRITICAL":
                self.stats["critical"] += 1
            elif sev == "HIGH":
                self.stats["high"] += 1
            elif sev == "MEDIUM":
                self.stats["medium"] += 1
            elif sev == "LOW":
                self.stats["low"] += 1
            else:
                self.stats["info"] += 1

        self.stats["total"] = sum(self.stats[k] for k in ("critical", "high", "medium", "low", "info"))

    # ─────────────────────────────────────────────────────────────────────
    # Secciones del PDF
    # ─────────────────────────────────────────────────────────────────────

    def _cover(self):
        elements = [Spacer(1, 1 * inch)]
        elements.append(Paragraph("REPORTE DE SEGURIDAD IaC", self.styles['CustomTitle']))
        elements.append(Paragraph("Terraform — Full Analysis (fmt · validate · tflint · Checkov)",
                                  self.styles['Heading2']))
        elements.append(Spacer(1, 0.5 * inch))
        return elements

    def _toc(self):
        elements = [Paragraph("TABLA DE CONTENIDOS", self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]
        elements.append(Paragraph("1. Resumen Ejecutivo", self.styles['Normal']))
        elements.append(Paragraph("2. Estadísticas Consolidadas", self.styles['Normal']))
        elements.append(Paragraph("3. terraform fmt + validate", self.styles['Normal']))
        elements.append(Paragraph("4. tflint — Linter", self.styles['Normal']))
        elements.append(Paragraph("5. Checkov — Seguridad IaC", self.styles['Normal']))
        elements.append(PageBreak())
        return elements

    def _executive_summary(self):
        elements = [Paragraph("1. RESUMEN EJECUTIVO", self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]

        has_risk = self.stats["critical"] > 0 or self.stats["high"] > 0 or self.stats["medium"] > 0
        if not has_risk:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = ("El análisis integral de Terraform concluyó sin hallazgos bloqueantes. "
                           "Los controles nativos, el linter, el escáner de seguridad y el segundo "
                           "opinion coinciden en que la infraestructura declarada cumple los umbrales "
                           "institucionales de la tabla CVSSv3.")
        else:
            status_html = "<font color='#c0392b'><b>FALLIDO</b></font>"
            status_desc = ("El análisis detectó hallazgos que superan los umbrales institucionales "
                           "(CVSSv3). Es obligatorio remediar los niveles Crítico, Alto y Medio antes "
                           "de desplegar la infraestructura para evitar exposición, incumplimiento "
                           "normativo o interrupciones operativas.")

        tools_str = ", ".join(self.tools_present) if self.tools_present else "N/A"

        summary = f"""
        <b>Estado del Análisis:</b> {status_html}<br/>
        {status_desc}<br/><br/>
        <b>Herramientas ejecutadas:</b> {tools_str}<br/>
        <b>Total de hallazgos:</b> {self.stats['total']}<br/><br/>
        <b>Distribución por severidad (CVSSv3):</b><br/>
        • <font color='#c0392b'><b>Críticos:</b></font> {self.stats['critical']}<br/>
        • <font color='#e74c3c'><b>Altos:</b></font>    {self.stats['high']}<br/>
        • <font color='#f39c12'><b>Medios:</b></font>   {self.stats['medium']}<br/>
        • <font color='#f1c40f'><b>Bajos:</b></font>    {self.stats['low']}<br/>
        • <font color='#7f8c8d'><b>Info:</b></font>     {self.stats['info']}<br/>
        """
        elements.append(Paragraph(summary, self.styles['BodyJustified']))
        return elements

    def _stats_table(self):
        elements = [PageBreak(),
                    Paragraph("2. ESTADÍSTICAS CONSOLIDADAS", self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]

        data = [['Herramienta', 'Crítico', 'Alto', 'Medio', 'Bajo', 'Info', 'Total']]

        def _row(name, c, h, m, l, i):
            return [name, str(c), str(h), str(m), str(l), str(i), str(c + h + m + l + i)]

        # terraform-native
        if self.native:
            unformatted = len(self.native.get("fmt", {}).get("unformatted_files", []) or [])
            v_err = sum(1 for e in self.native.get("validate", {}).get("by_dir", []) or []
                        for d in e.get("diagnostics", []) or []
                        if (d.get("severity") or "").lower() == "error")
            v_warn = sum(1 for e in self.native.get("validate", {}).get("by_dir", []) or []
                         for d in e.get("diagnostics", []) or []
                         if (d.get("severity") or "").lower() == "warning")
            data.append(_row("fmt + validate", v_err, 0, 0, v_warn, unformatted))

        # tflint
        if self.tflint:
            e = sum(1 for it in self.tflint if (it.get("rule", {}).get("severity") or "").lower() == "error")
            w = sum(1 for it in self.tflint if (it.get("rule", {}).get("severity") or "").lower() == "warning")
            n = len(self.tflint) - e - w
            data.append(_row("tflint", 0, 0, e, w, n))

        # Checkov
        if self.checkov:
            c = sum(1 for x in self.checkov if (x.get("severity") or "HIGH").upper() == "CRITICAL")
            h = sum(1 for x in self.checkov if (x.get("severity") or "HIGH").upper() == "HIGH")
            m = sum(1 for x in self.checkov if (x.get("severity") or "HIGH").upper() == "MEDIUM")
            l = sum(1 for x in self.checkov if (x.get("severity") or "HIGH").upper() == "LOW")
            data.append(_row("Checkov", c, h, m, l, 0))

        # Total
        data.append(_row("TOTAL",
                         self.stats["critical"], self.stats["high"],
                         self.stats["medium"], self.stats["low"], self.stats["info"]))

        tbl = Table(data, colWidths=[1.9 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch, 0.9 * inch])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#7f8c8d')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        elements.append(tbl)
        return elements

    def _section_terraform_native(self):
        if not self.native:
            return []
        elements = [PageBreak(),
                    Paragraph("3. terraform fmt + validate", self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]

        unformatted = self.native.get("fmt", {}).get("unformatted_files", []) or []
        by_dir = self.native.get("validate", {}).get("by_dir", []) or []
        totals = self.native.get("validate", {}).get("totals", {}) or {}

        elements.append(Paragraph(
            f"<b>Archivos sin formato canónico:</b> {len(unformatted)}<br/>"
            f"<b>Errores de validate:</b> {totals.get('error_count', 0)}<br/>"
            f"<b>Warnings de validate:</b> {totals.get('warning_count', 0)}<br/>",
            self.styles['BodyText']))

        if unformatted:
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph("<b>Archivos que requieren <code>terraform fmt</code>:</b>",
                                      self.styles['BodyText']))
            for f in unformatted[:30]:
                elements.append(Paragraph(f"• <font face='Courier'>{html.escape(f)}</font>",
                                          self.styles['BodyText']))
            if len(unformatted) > 30:
                elements.append(Paragraph(f"<i>… y {len(unformatted) - 30} más</i>",
                                          self.styles['BodyText']))

        if any(entry.get("diagnostics") for entry in by_dir):
            elements.append(Spacer(1, 0.2 * inch))
            elements.append(Paragraph("<b>Diagnósticos de <code>terraform validate</code>:</b>",
                                      self.styles['BodyText']))
            for entry in by_dir:
                if not entry.get("diagnostics"):
                    continue
                elements.append(Paragraph(f"<b>Directorio:</b> <font face='Courier'>{html.escape(entry.get('dir','?'))}</font>",
                                          self.styles['BodyText']))
                for diag in entry.get("diagnostics", [])[:10]:
                    sev = (diag.get("severity") or "info").upper()
                    summary = html.escape(diag.get("summary", ""))
                    detail  = html.escape(diag.get("detail", ""))[:250]
                    elements.append(Paragraph(f"[{sev}] {summary} — <font color='#7f8c8d'>{detail}</font>",
                                              self.styles['BodyText']))

        return elements

    def _section_tflint(self):
        if not self.tflint:
            return []
        elements = [PageBreak(),
                    Paragraph("4. tflint — Terraform Linter", self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]
        elements.append(Paragraph(f"<b>Total de issues:</b> {len(self.tflint)}",
                                  self.styles['BodyText']))
        elements.append(Spacer(1, 0.15 * inch))

        # Ordenar por severidad
        sev_order = {"error": 0, "warning": 1, "notice": 2, "info": 3}
        issues_sorted = sorted(self.tflint,
                               key=lambda x: sev_order.get((x.get("rule", {}).get("severity") or "notice").lower(), 99))

        for it in issues_sorted[:40]:
            rule = it.get("rule", {}) or {}
            sev  = (rule.get("severity") or "notice").upper()
            name = html.escape(rule.get("name", "?"))
            msg  = html.escape(it.get("message", ""))
            rng  = it.get("range") or {}
            fname = html.escape(str(rng.get("filename", "?")))
            line  = (rng.get("start") or {}).get("line", "?")
            d     = html.escape(it.get("_dir", "?"))
            elements.append(Paragraph(
                f"<b>[{sev}] {name}</b><br/>"
                f"<font size='9' color='#7f8c8d'>{d} · {fname}:{line}</font><br/>"
                f"{msg}",
                self.styles['BodyText']))
            elements.append(Spacer(1, 0.08 * inch))

        if len(self.tflint) > 40:
            elements.append(Paragraph(f"<i>… y {len(self.tflint) - 40} issues más</i>",
                                      self.styles['BodyText']))
        return elements

    def _section_checkov(self):
        if not self.checkov:
            return []
        elements = [PageBreak(),
                    Paragraph("5. Checkov — Seguridad IaC", self.styles['CustomHeading2']),
                    Spacer(1, 0.2 * inch)]
        elements.append(Paragraph(f"<b>Total de checks fallidos:</b> {len(self.checkov)}",
                                  self.styles['BodyText']))
        elements.append(Spacer(1, 0.15 * inch))

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        checks_sorted = sorted(self.checkov,
                               key=lambda x: sev_order.get((x.get("severity") or "HIGH").upper(), 99))

        for c in checks_sorted[:40]:
            sev = (c.get("severity") or "HIGH").upper()
            cid = html.escape(c.get("check_id", "?"))
            cname = html.escape(c.get("check_name", ""))[:120]
            resource = html.escape(c.get("resource", "?"))
            file_path = html.escape(c.get("file_path", "?"))
            rng = c.get("file_line_range", ["?", "?"])
            line_str = f"{rng[0]}-{rng[1]}" if isinstance(rng, list) and len(rng) == 2 else "?"
            elements.append(Paragraph(
                f"<b>[{sev}] {cid}</b> — {cname}<br/>"
                f"<font size='9' color='#7f8c8d'>{resource} · {file_path}:{line_str}</font>",
                self.styles['BodyText']))
            elements.append(Spacer(1, 0.08 * inch))

        if len(self.checkov) > 40:
            elements.append(Paragraph(f"<i>… y {len(self.checkov) - 40} checks más</i>",
                                      self.styles['BodyText']))
        return elements

    def generate_pdf(self):
        try:
            self.load_all()
            self.calculate_stats()

            doc = SimpleDocTemplate(
                self.pdf_output_path, pagesize=letter,
                topMargin=100, bottomMargin=50, rightMargin=40, leftMargin=40,
                title='Reporte Terraform Full — IaC Security',
            )

            elements = []
            elements.extend(self._cover())
            elements.extend(self._toc())
            elements.extend(self._executive_summary())
            elements.extend(self._stats_table())
            elements.extend(self._section_terraform_native())
            elements.extend(self._section_tflint())
            elements.extend(self._section_checkov())

            doc.build(elements, onFirstPage=self.draw_header, onLaterPages=self.draw_header)
            print(f"✓ PDF Terraform Full generado exitosamente: {self.pdf_output_path}")

        except Exception as exc:
            print(f"✗ Error al generar PDF Terraform Full: {exc}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 terraform_full_to_pdf_report.py <primary_json> <output_pdf> [logo_path]")
        sys.exit(1)

    primary_json = sys.argv[1]
    output_pdf   = sys.argv[2]
    logo         = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"

    gen = TerraformFullReportGenerator(primary_json, output_pdf, logo)
    gen.generate_pdf()


if __name__ == '__main__':
    main()
