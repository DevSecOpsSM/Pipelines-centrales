#!/usr/bin/env python3
"""
Script para convertir reportes JSON de Hadolint (Dockerfile Linter) a PDF
estructurado institucional. Sigue los lineamientos corporativos de DevSecOps.
Uso: python3 hadolint_to_pdf_report.py <json_report> <output_pdf> [logo_path]
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


class HadolintReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    def __init__(self, json_report_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)

        self.test_type = "DevSecOps-Hadolint"
        self.data = None
        self.findings = []
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

            # Hadolint devuelve una lista o vacío
            if isinstance(self.data, list):
                self.findings = self.data
            else:
                self.findings = []
            print("✓ Reporte Hadolint cargado exitosamente.")
        except Exception as e:
            print(f"✗ Error al cargar JSON Hadolint: {str(e)}")
            sys.exit(1)

    def map_hadolint_severity(self, level):
        """
        Mapeo Hadolint → institucional:
            error   → ALTA    (Dockerfile con problemas serios: SC*, DL3059, etc.)
            warning → MEDIA   (buenas prácticas ausentes)
            info    → BAJA    (sugerencias menores)
            style   → BAJA    (formato)
        """
        level = (level or 'info').lower()
        if level == 'error':
            return self.SEV_ALTA
        if level == 'warning':
            return self.SEV_MEDIA
        return self.SEV_BAJA

    def calculate_statistics(self):
        critical = high = medium = low = 0
        by_file = defaultdict(int)
        by_code = defaultdict(int)

        for f in self.findings:
            severity = self.map_hadolint_severity(f.get('level'))
            if severity == self.SEV_CRITICA:
                critical += 1
            elif severity == self.SEV_ALTA:
                high += 1
            elif severity == self.SEV_MEDIA:
                medium += 1
            else:
                low += 1

            file_path = str(f.get('file', 'Dockerfile'))
            by_file[file_path] += 1

            code = str(f.get('code', 'UNKNOWN'))
            by_code[code] += 1

        self.stats = {
            'total_findings':   len(self.findings),
            'critical':         critical,
            'high':             high,
            'medium':           medium,
            'low':              low,
            'files_scanned':    len(by_file),
            'findings_by_file': dict(sorted(by_file.items(), key=lambda x: x[1], reverse=True)),
            'top_codes':        dict(sorted(by_code.items(), key=lambda x: x[1], reverse=True)),
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

        if self.stats['total_findings'] == 0:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = ("El análisis de Hadolint no detectó violaciones de mejores "
                           "prácticas en los Dockerfiles del repositorio, o no se "
                           "encontraron Dockerfiles. Los archivos evaluados cumplen "
                           "con los estándares corporativos de imágenes seguras.")
        elif not has_risk:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = ("El análisis de Hadolint no detectó violaciones significativas.")
        else:
            status_html = "<font color='#c0392b'><b>REVISAR</b></font>"
            status_desc = ("Hadolint identificó violaciones de mejores prácticas en los "
                           "Dockerfiles. Es necesario revisar y corregir estos hallazgos "
                           "para asegurar la construcción de imágenes seguras y minimizar "
                           "el ataque de superficie del contenedor.")

        summary_text = f"""
        <b>Estado del Análisis:</b> {status_html}<br/>
        {status_desc}<br/><br/>
        <b>Archivos Dockerfile Analizados:</b> {self.stats['files_scanned']}<br/>
        <b>Total de Hallazgos:</b> {self.stats['total_findings']}<br/>
        <br/>
        <b>Distribución por Severidad:</b><br/>
        • <font color='#c0392b'><b>Críticas:</b></font> {self.stats['critical']} hallazgos<br/>
        • <font color='#e74c3c'><b>Altas:</b></font> {self.stats['high']} hallazgos<br/>
        • <font color='#f39c12'><b>Medias:</b></font> {self.stats['medium']} hallazgos<br/>
        • <font color='#f1c40f'><b>Bajas/Style:</b></font> {self.stats['low']} hallazgos<br/>
        """
        elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
        return elements

    def create_statistics_section(self):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("ESTADÍSTICAS DETALLADAS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2 * inch))

        # Tabla por severidad
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

        # Códigos Hadolint más frecuentes
        top_codes = list(self.stats['top_codes'].items())[:15]
        if top_codes:
            elements.append(Paragraph("CÓDIGOS HADOLINT MÁS FRECUENTES", self.styles['Heading3']))
            elements.append(Spacer(1, 0.1 * inch))
            code_data = [['Código', 'Ocurrencias']]
            for code, count in top_codes:
                code_data.append([code, str(count)])
            code_table = Table(code_data, colWidths=[3.5 * inch, 1.5 * inch])
            code_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            elements.append(code_table)

        return elements

    def _extract_findings_by_severity(self):
        by_sev = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for f in self.findings:
            severity = self.map_hadolint_severity(f.get('level'))
            by_sev[severity].append(f)
        return by_sev

    def _create_severity_block(self, severity, findings):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph(f"HALLAZGOS DOCKERFILE - {severity} ({len(findings)})",
                                  self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2 * inch))

        for idx, f in enumerate(findings, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.15 * inch))

            code = html.escape(str(f.get('code', '?')))
            file_path = html.escape(str(f.get('file', '?')).lstrip('./'))
            line = f.get('line', '?')
            col = f.get('column', '?')
            message = html.escape(str(f.get('message', ''))[:300])
            level = html.escape(str(f.get('level', '?')).upper())

            elements.append(Paragraph(f"<b>{idx}. [{code}] {message[:70]}</b>",
                                      self.styles['Heading3']))

            details = f"""
            <b>Archivo:</b> {file_path} (Línea {line}, Col {col})<br/>
            <b>Nivel nativo Hadolint:</b> {level}<br/>
            <b>Descripción:</b> {message}<br/>
            <b>Referencia:</b> https://github.com/hadolint/hadolint/wiki/{code}<br/>
            """
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
                title='Reporte Hadolint Dockerfile'
            )

            elements = []

            elements.append(Spacer(1, 1 * inch))
            elements.append(Paragraph("REPORTE DE ANÁLISIS DE DOCKERFILE",
                                      self.styles['CustomTitle']))
            elements.append(Paragraph("Hadolint - Dockerfile Best Practices Linter",
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
            print(f"✓ PDF Hadolint generado exitosamente: {self.pdf_output_path}")

        except Exception as e:
            print(f"✗ Error al generar PDF Hadolint: {str(e)}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 hadolint_to_pdf_report.py <json_report> <output_pdf> [logo_path]")
        sys.exit(1)

    json_report = sys.argv[1]
    output_pdf = sys.argv[2]
    logo = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"

    generator = HadolintReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()


if __name__ == '__main__':
    main()
