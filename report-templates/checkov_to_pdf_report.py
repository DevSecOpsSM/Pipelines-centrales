#!/usr/bin/env python3
"""
Script para convertir reportes JSON de Checkov (IaC) a PDF estructurado institucional
Uso: python3 checkov_to_pdf_report.py <json_report> <output_pdf> [logo_path]
"""

import json
import sys
import os
import html
from datetime import datetime
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib import colors

class CheckovReportGenerator:
    # CONSTANTES PARA SEVERIDADES
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    def __init__(self, json_report_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)
        
        self.test_type = "DevSecOps-CHECKOV"
        self.raw_data = None
        self.failed_checks = []
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
            canvas.drawImage(self.logo_path, 40, height - 70, width=140, height=40, preserveAspectRatio=True, mask='auto')
            
        data = [
            ['Código:', self.test_type],
            ['Vigente desde:', datetime.now().strftime('%d/%m/%Y')],
            ['Clasificación:', 'Confidencial']
        ]
        
        t = Table(data, colWidths=[80, 100])
        t.setStyle(TableStyle([
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
            ('SIZE', (0,0), (-1,-1), 9),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#333333')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('TOPPADDING', (0,0), (-1,-1), 2),
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
                self.raw_data = json.load(f)
            
            if isinstance(self.raw_data, dict):
                self.raw_data = [self.raw_data]
            elif not isinstance(self.raw_data, list):
                self.raw_data = []
                
        except Exception as e:
            print(f"✗ Error al cargar JSON Checkov: {str(e)}")
            sys.exit(1)

    def _extract_severity(self, check):
        """Extrae y normaliza la severidad de Checkov"""
        sev = check.get('severity')
        if isinstance(sev, dict):
            sev = sev.get('value', 'MEDIUM')
        elif not isinstance(sev, str):
            sev = 'MEDIUM'
            
        sev = sev.upper()
        if 'CRIT' in sev: return self.SEV_CRITICA
        elif 'HIGH' in sev: return self.SEV_ALTA
        elif 'MED' in sev: return self.SEV_MEDIA
        elif 'LOW' in sev: return self.SEV_BAJA
        return self.SEV_MEDIA

    def calculate_statistics(self):
        total_passed = 0
        total_failed = 0
        frameworks_found = set()
        
        sev_counts = {
            self.SEV_CRITICA: 0,
            self.SEV_ALTA: 0,
            self.SEV_MEDIA: 0,
            self.SEV_BAJA: 0
        }
        
        for report in self.raw_data:
            framework = report.get('check_type', 'unknown')
            frameworks_found.add(framework)
            
            summary = report.get('summary', {})
            total_passed += summary.get('passed', 0)
            
            results = report.get('results', {})
            failed_list = results.get('failed_checks', [])
            
            for check in failed_list:
                check['framework'] = framework
                severity = self._extract_severity(check)
                sev_counts[severity] += 1
                self.failed_checks.append(check)
                total_failed += 1
                
        self.stats = {
            'frameworks': list(frameworks_found),
            'total_passed': total_passed,
            'total_failed': total_failed,
            'total_checks': total_passed + total_failed,
            'critical': sev_counts[self.SEV_CRITICA],
            'high': sev_counts[self.SEV_ALTA],
            'medium': sev_counts[self.SEV_MEDIA],
            'low': sev_counts[self.SEV_BAJA]
        }

    def create_executive_summary(self):
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        fw_str = ", ".join(self.stats['frameworks']) if self.stats['frameworks'] else "N/A"
        
 
        has_risk = (
            self.stats['critical'] > 0 or 
            self.stats['high'] > 0 or 
            self.stats['medium'] > 0 or 
            self.stats['low'] > 0
        )
        
        if not has_risk:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = "El análisis de Infraestructura como Código (IaC) ha concluido exitosamente. No se detectaron configuraciones inseguras de ningún nivel, cumpliendo con los estándares de seguridad más estrictos definidos para el despliegue."
        else:
            status_html = "<font color='#c0392b'><b>FALLIDO</b></font>"
            status_desc = "El análisis ha detectado configuraciones inseguras. Es obligatorio revisar y corregir estos hallazgos para evitar la exposición de recursos, brechas de datos o incumplimiento normativo antes de desplegar la infraestructura."

        summary_text = f"""
        <b>Estado del Análisis:</b> {status_html}<br/>
        {status_desc}<br/><br/>
        <b>Frameworks Analizados (IaC):</b> {fw_str}<br/>
        <b>Total de Evaluaciones (Controles):</b> {self.stats['total_checks']}<br/>
        <b>Controles Aprobados:</b> <font color='#27ae60'>{self.stats['total_passed']}</font><br/>
        <b>Controles Fallidos (Inseguros):</b> <font color='#c0392b'>{self.stats['total_failed']}</font><br/>
        <br/>
        <b>Distribución de Fallos por Severidad:</b><br/>
        • <font color='#c0392b'><b>Críticas:</b></font> {self.stats['critical']} hallazgos<br/>
        • <font color='#e74c3c'><b>Altas:</b></font> {self.stats['high']} hallazgos<br/>
        • <font color='#f39c12'><b>Medias:</b></font> {self.stats['medium']} hallazgos<br/>
        • <font color='#f1c40f'><b>Bajas:</b></font> {self.stats['low']} hallazgos<br/>
        """
        # ---------------------------------------
        elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
        
        return elements

    def create_statistics_section(self):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("ESTADÍSTICAS DETALLADAS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        severity_data = [['Severidad', 'Cantidad', 'Porcentaje']]
        for severity, key in [(self.SEV_CRITICA, 'critical'), (self.SEV_ALTA, 'high'), (self.SEV_MEDIA, 'medium'), (self.SEV_BAJA, 'low')]:
            count = self.stats[key]
            percentage = (count / self.stats['total_failed'] * 100) if self.stats['total_failed'] > 0 else 0
            severity_data.append([severity, str(count), f'{percentage:.1f}%'])
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        
        elements.append(severity_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements

    def _extract_findings_by_severity(self):
        vulns_by_severity = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for check in self.failed_checks:
            severity = self._extract_severity(check)
            vulns_by_severity[severity].append(check)
        return vulns_by_severity

    def _create_severity_block(self, severity, checks):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph(f"HALLAZGOS DE INFRAESTRUCTURA - {severity} ({len(checks)})", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        for idx, check in enumerate(checks, 1):
            if idx > 1: elements.append(Spacer(1, 0.15*inch))
            
            check_id = html.escape(str(check.get('check_id', 'N/A')))
            check_name = html.escape(str(check.get('check_name', 'Sin descripción')))
            file_path = html.escape(str(check.get('file_path', 'N/A')))
            resource = html.escape(str(check.get('resource', 'N/A')))
            framework = html.escape(str(check.get('framework', 'N/A')).upper())
            guideline = check.get('guideline')
            
            lines = check.get('file_line_range', [])
            lines_str = f"{lines[0]} - {lines[1]}" if len(lines) == 2 else "N/A"
            
            elements.append(Paragraph(f"<b>{idx}. [{check_id}] {check_name[:80]}</b>", self.styles['Heading3']))
            
            details = f"""
            <b>Framework / Tipo:</b> {framework}<br/>
            <b>Archivo:</b> {file_path} (Líneas: {lines_str})<br/>
            <b>Recurso Afectado:</b> {resource}<br/>
            """
            
            if guideline:
                clean_url = html.escape(str(guideline))
                details += f"<b>Guía de Remediación:</b> {clean_url}<br/>"
                
            elements.append(Paragraph(details, self.styles['BodyText']))
        
        return elements

    def create_findings_section(self):
        elements = []
        vulns_by_severity = self._extract_findings_by_severity()
        
        for severity in [self.SEV_CRITICA, self.SEV_ALTA, self.SEV_MEDIA]:
            checks = vulns_by_severity[severity]
            if checks:
                elements.extend(self._create_severity_block(severity, checks))
                
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
                title='Reporte Checkov IaC Security'
            )
            
            elements = []
            
            elements.append(Spacer(1, 1*inch))
            elements.append(Paragraph("REPORTE DE SEGURIDAD IaC", self.styles['CustomTitle']))
            elements.append(Paragraph("Checkov - Análisis de Infraestructura como Código", self.styles['Heading2']))
            elements.append(Spacer(1, 0.5*inch))
            
            elements.append(Paragraph("TABLA DE CONTENIDOS", self.styles['CustomHeading2']))
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph("1. Resumen Ejecutivo", self.styles['Normal']))
            elements.append(Paragraph("2. Estadísticas Detalladas", self.styles['Normal']))
            elements.append(Paragraph("3. Desglose de Hallazgos por Severidad", self.styles['Normal']))
            
            elements.append(PageBreak())
            
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())
            
            doc.build(elements, onFirstPage=self.draw_header, onLaterPages=self.draw_header)
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
    logo = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"
    
    generator = CheckovReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()

if __name__ == '__main__':
    main()