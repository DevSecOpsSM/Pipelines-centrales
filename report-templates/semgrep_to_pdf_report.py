#!/usr/bin/env python3
"""
Script para convertir reportes JSON de Semgrep (SAST) a PDF estructurado institucional.
Sigue los lineamientos corporativos de DevSecOps.
Uso: python3 semgrep_to_pdf_report.py <json_report> <output_pdf> [logo_path]
"""

import json
import sys
import os
import html
from datetime import datetime

# Forzar UTF-8 en stdout/stderr para evitar UnicodeEncodeError en Windows
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib import colors


class SemgrepReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    def __init__(self, json_report_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)

        self.test_type = "DevSecOps-Semgrep"
        self.data = None
        self.results = []
        self.errors = []
        self.stats = {}

        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold',
            borderColor=colors.HexColor('#00e5bd'),
            borderWidth=2,
            borderPadding=8,
            borderRadius=3
        ))

        self.styles.add(ParagraphStyle(
            name='BodyJustified',
            parent=self.styles['BodyText'],
            alignment=TA_JUSTIFY,
            fontSize=10,
            leading=12,
            textColor=colors.HexColor('#2c3e50')
        ))

    def draw_header(self, canvas, doc):
        canvas.saveState()
        width, height = letter

        if os.path.exists(self.logo_path):
            canvas.drawImage(self.logo_path, 40, height - 70, width=140, height=40,
                             preserveAspectRatio=True, mask='auto')

        data = [
            ['Código:', self.test_type],
            ['Vigente desde:', datetime.now().strftime('%d/%m/%Y')],
            ['Clasificación:', 'Confidencial']
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

    def load_json_report(self):
        try:
            with open(self.json_report_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            self.results = self.data.get('results', [])
            self.errors = self.data.get('errors', [])
            print("✓ Reporte Semgrep cargado exitosamente.")
        except Exception as e:
            print(f"✗ Error al cargar JSON Semgrep: {str(e)}")
            sys.exit(1)

    def map_semgrep_severity(self, raw_severity):
        """
        Mapeo Semgrep → institucional:
            ERROR    → ALTA     (problemas serios de seguridad)
            WARNING  → MEDIA    (problemas relevantes)
            INFO     → BAJA     (sugerencias / mejores prácticas)
        Semgrep no expone CRÍTICA nativamente; se reserva para casos donde
        metadata['confidence'] sea 'HIGH' y severity sea 'ERROR' simultáneamente.
        """
        sev = (raw_severity or "INFO").upper()
        if sev == "ERROR":
            return self.SEV_ALTA
        if sev == "WARNING":
            return self.SEV_MEDIA
        return self.SEV_BAJA

    def calculate_statistics(self):
        total = 0
        critical = high = medium = low = 0
        finding_by_rule = defaultdict(int)
        owasp_categories = defaultdict(int)

        for r in self.results:
            total += 1
            extra = r.get('extra', {}) or {}
            sev_native = (extra.get('severity') or 'INFO').upper()
            severity = self.map_semgrep_severity(sev_native)

            # Escalar a CRÍTICA si la regla trae metadata de alta confianza
            meta = extra.get('metadata', {}) or {}
            confidence = (meta.get('confidence') or '').upper()
            if severity == self.SEV_ALTA and confidence == 'HIGH':
                severity = self.SEV_CRITICA

            if severity == self.SEV_CRITICA:
                critical += 1
            elif severity == self.SEV_ALTA:
                high += 1
            elif severity == self.SEV_MEDIA:
                medium += 1
            else:
                low += 1

            check_id = r.get('check_id', 'unknown')
            rule_short = check_id.split('.')[-1] if '.' in check_id else check_id
            finding_by_rule[rule_short] += 1

            owasp = meta.get('owasp')
            if isinstance(owasp, list):
                for o in owasp:
                    owasp_categories[str(o)[:40]] += 1
            elif isinstance(owasp, str):
                owasp_categories[owasp[:40]] += 1

        self.stats = {
            'total_findings':   total,
            'critical':         critical,
            'high':             high,
            'medium':           medium,
            'low':              low,
            'errors_semgrep':   len(self.errors),
            'top_rules':        dict(sorted(finding_by_rule.items(), key=lambda x: x[1], reverse=True)),
            'owasp_categories': dict(sorted(owasp_categories.items(), key=lambda x: x[1], reverse=True)),
        }

    def create_executive_summary(self):
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2 * inch))

        has_risk = (
            self.stats['critical'] > 0 or
            self.stats['high'] > 0 or
            self.stats['medium'] > 0 or
            self.stats['low'] > 0
        )

        if not has_risk:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = ("El análisis SAST de Semgrep ha concluido exitosamente. "
                           "No se detectaron patrones de código inseguros contra las "
                           "reglas OWASP Top 10, secrets y CI. El código cumple con "
                           "los estándares de seguridad definidos.")
        else:
            status_html = "<font color='#c0392b'><b>FALLIDO</b></font>"
            status_desc = ("El motor SAST ha detectado patrones de código que violan "
                           "los controles OWASP Top 10 y/o buenas prácticas de seguridad. "
                           "Es obligatorio revisar y corregir los hallazgos antes del "
                           "despliegue a producción.")

        summary_text = f"""
        <b>Estado del Análisis:</b> {status_html}<br/>
        {status_desc}<br/><br/>
        <b>Reglas aplicadas:</b> p/owasp-top-ten · p/secrets · p/ci<br/>
        <b>Total de Hallazgos:</b> {self.stats['total_findings']}<br/>
        <b>Advertencias del motor:</b> {self.stats['errors_semgrep']}<br/>
        <br/>
        <b>Distribución por Severidad:</b><br/>
        • <font color='#c0392b'><b>Críticas:</b></font> {self.stats['critical']} hallazgos<br/>
        • <font color='#e74c3c'><b>Altas:</b></font> {self.stats['high']} hallazgos<br/>
        • <font color='#f39c12'><b>Medias:</b></font> {self.stats['medium']} hallazgos<br/>
        • <font color='#f1c40f'><b>Bajas/Info:</b></font> {self.stats['low']} hallazgos<br/>
        """
        elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
        return elements

    def create_statistics_section(self):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("ESTADÍSTICAS DETALLADAS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2 * inch))

        # Tabla por Severidad
        severity_data = [['Severidad', 'Cantidad', 'Porcentaje']]
        for severity, key in [(self.SEV_CRITICA, 'critical'), (self.SEV_ALTA, 'high'),
                              (self.SEV_MEDIA, 'medium'), (self.SEV_BAJA, 'low')]:
            count = self.stats[key]
            total = self.stats['total_findings']
            percentage = (count / total * 100) if total > 0 else 0
            severity_data.append([severity, str(count), f'{percentage:.1f}%'])

        severity_table = Table(severity_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        elements.append(severity_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Top reglas disparadas
        top_rules = list(self.stats['top_rules'].items())[:15]
        if top_rules:
            elements.append(Paragraph("REGLAS SEMGREP MÁS DISPARADAS", self.styles['Heading3']))
            elements.append(Spacer(1, 0.1 * inch))
            rule_data = [['Regla', 'Ocurrencias']]
            for rule, count in top_rules:
                rule_data.append([rule[:60], str(count)])
            rule_table = Table(rule_data, colWidths=[3.5 * inch, 1.5 * inch])
            rule_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            elements.append(rule_table)
            elements.append(Spacer(1, 0.3 * inch))

        # Categorías OWASP detectadas
        owasp_list = list(self.stats['owasp_categories'].items())[:10]
        if owasp_list:
            elements.append(Paragraph("CATEGORÍAS OWASP TOP 10 DETECTADAS", self.styles['Heading3']))
            elements.append(Spacer(1, 0.1 * inch))
            owasp_data = [['Categoría', 'Hallazgos']]
            for cat, count in owasp_list:
                owasp_data.append([cat, str(count)])
            owasp_table = Table(owasp_data, colWidths=[3.5 * inch, 1.5 * inch])
            owasp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            elements.append(owasp_table)

        return elements

    def _extract_findings_by_severity(self):
        by_sev = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for r in self.results:
            extra = r.get('extra', {}) or {}
            sev_native = (extra.get('severity') or 'INFO').upper()
            severity = self.map_semgrep_severity(sev_native)

            meta = extra.get('metadata', {}) or {}
            confidence = (meta.get('confidence') or '').upper()
            if severity == self.SEV_ALTA and confidence == 'HIGH':
                severity = self.SEV_CRITICA

            by_sev[severity].append(r)
        return by_sev

    def _create_severity_block(self, severity, findings):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph(f"HALLAZGOS SAST - {severity} ({len(findings)})",
                                  self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2 * inch))

        for idx, r in enumerate(findings, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.15 * inch))

            check_id = html.escape(str(r.get('check_id', '?')))
            rule_short = check_id.split('.')[-1] if '.' in check_id else check_id
            path = html.escape(str(r.get('path', '?')))
            start_line = r.get('start', {}).get('line', '?')
            end_line = r.get('end', {}).get('line', start_line)
            line_str = f"{start_line}" if start_line == end_line else f"{start_line}-{end_line}"

            extra = r.get('extra', {}) or {}
            message = html.escape(str(extra.get('message', ''))[:300])
            fix = extra.get('fix')
            meta = extra.get('metadata', {}) or {}

            elements.append(Paragraph(f"<b>{idx}. [{html.escape(rule_short)}]</b>",
                                      self.styles['Heading3']))

            details = f"""
            <b>Archivo:</b> {path} (Línea {line_str})<br/>
            <b>Regla completa:</b> {check_id}<br/>
            <b>Descripción:</b> {message}<br/>
            """

            owasp = meta.get('owasp')
            if owasp:
                owasp_str = owasp[0] if isinstance(owasp, list) else str(owasp)
                details += f"<b>OWASP:</b> {html.escape(str(owasp_str)[:80])}<br/>"

            cwe = meta.get('cwe')
            if cwe:
                cwe_str = cwe[0] if isinstance(cwe, list) else str(cwe)
                details += f"<b>CWE:</b> {html.escape(str(cwe_str)[:60])}<br/>"

            if fix:
                details += f"<b>Sugerencia de fix:</b> {html.escape(str(fix)[:200])}<br/>"

            references = meta.get('references') or []
            if references and isinstance(references, list):
                details += f"<b>Referencia:</b> {html.escape(str(references[0])[:100])}<br/>"

            elements.append(Paragraph(details, self.styles['BodyText']))

        return elements

    def create_findings_section(self):
        elements = []
        by_sev = self._extract_findings_by_severity()
        for severity in [self.SEV_CRITICA, self.SEV_ALTA, self.SEV_MEDIA]:
            findings = by_sev[severity]
            if findings:
                elements.extend(self._create_severity_block(severity, findings))
        return elements

    def generate_pdf(self):
        try:
            self.load_json_report()
            self.calculate_statistics()

            doc = SimpleDocTemplate(
                self.pdf_output_path,
                pagesize=letter,
                topMargin=100,
                bottomMargin=50,
                rightMargin=40,
                leftMargin=40,
                title='Reporte Semgrep SAST'
            )

            elements = []

            elements.append(Spacer(1, 1 * inch))
            elements.append(Paragraph("REPORTE DE SEGURIDAD SAST", self.styles['CustomTitle']))
            elements.append(Paragraph("Semgrep - OWASP Top 10 + Secrets + CI",
                                      self.styles['Heading2']))
            elements.append(Spacer(1, 0.5 * inch))

            elements.append(Paragraph("TABLA DE CONTENIDOS", self.styles['CustomHeading2']))
            elements.append(Spacer(1, 0.2 * inch))
            elements.append(Paragraph("1. Resumen Ejecutivo", self.styles['Normal']))
            elements.append(Paragraph("2. Estadísticas Detalladas", self.styles['Normal']))
            elements.append(Paragraph("3. Desglose de Hallazgos por Severidad",
                                      self.styles['Normal']))

            elements.append(PageBreak())

            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())

            doc.build(elements, onFirstPage=self.draw_header, onLaterPages=self.draw_header)
            print(f"✓ PDF Semgrep generado exitosamente: {self.pdf_output_path}")

        except Exception as e:
            print(f"✗ Error al generar PDF Semgrep: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 semgrep_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)

    json_report = sys.argv[1]
    output_pdf = sys.argv[2]
    logo = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"

    generator = SemgrepReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()


if __name__ == '__main__':
    main()
