#!/usr/bin/env python3
"""
Script para convertir reportes JSON de KICS a PDF estructurado institucional
Uso: python3 kics_to_pdf_report.py <json_report> <output_pdf> [logo_path]
"""

import json
import sys
import os
from datetime import datetime
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Preformatted
)
from reportlab.lib import colors

class KICSReportGenerator:
    def __init__(self, json_report_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)
        
        self.test_type = "DevSecOps-KICKS"
        self.data = None
        self.vulnerabilities = []
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
        """Dibuja el encabezado institucional en cada página"""
        canvas.saveState()
        width, height = letter
        
        if os.path.exists(self.logo_path):
            canvas.drawImage(self.logo_path, 40, height - 70, width=140, height=40, preserveAspectRatio=True, mask='auto')
        else:
            print(f"⚠️ ADVERTENCIA: No se encontró el logo en: {self.logo_path}")
            
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
                self.data = json.load(f)
            
            self.vulnerabilities = []
            for query in self.data.get('queries', []):
                for file_info in query.get('files', []):
                    vuln = {
                        'queryName': query.get('query_name', 'Sin título'),
                        'severity': query.get('severity', 'UNKNOWN'),
                        'category': query.get('category', 'Uncategorized'),
                        'platform': query.get('platform', 'Unknown'),
                        'description': query.get('description', 'Sin descripción'),
                        'file': file_info.get('file_name', 'Archivo desconocido'),
                        'line': file_info.get('line', 'N/A'),
                        'value': file_info.get('actual_value', '')
                    }
                    self.vulnerabilities.append(vuln)
                    
            print(f"✓ Reporte cargado: {len(self.vulnerabilities)} hallazgos encontrados")
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            sys.exit(1)

    def calculate_statistics(self):
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        platform_counts = defaultdict(int)
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            category = vuln.get('category', 'Uncategorized')
            platform = vuln.get('platform', 'Unknown')
            
            severity_counts[severity] += 1
            category_counts[category] += 1
            platform_counts[platform] += 1
        
        self.stats = {
            'total': len(self.vulnerabilities),
            'by_severity': dict(severity_counts),
            'by_category': dict(category_counts),
            'by_platform': dict(platform_counts),
            'critical': severity_counts.get('CRITICAL', 0),
            'high': severity_counts.get('HIGH', 0),
            'medium': severity_counts.get('MEDIUM', 0),
            'low': severity_counts.get('LOW', 0),
            'info': severity_counts.get('INFO', 0),
        }

    def create_executive_summary(self):
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        

        has_risk = (
            self.stats['critical'] > 0 or 
            self.stats['high'] > 0 or 
            self.stats['medium'] > 0 or 
            self.stats['low'] > 0 or 
            self.stats['info'] > 0
        )
        
        if not has_risk:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = "La validación de configuraciones (KICS) se ejecutó sin detectar fallos ni avisos de ningún tipo. Los archivos de infraestructura cumplen estrictamente con las mejores prácticas de seguridad en la nube."
        else:
            status_html = "<font color='#c0392b'><b>FALLIDO</b></font>"
            status_desc = "Se han identificado brechas o avisos de configuración. Desplegar bajo estas condiciones expone el entorno a configuraciones por defecto inseguras o falta de controles de acceso. Se requiere validación."

        summary_text = f"""
        <b>Estado del Análisis:</b> {status_html}<br/>
        {status_desc}<br/><br/>
        <b>Proyecto:</b> Análisis de Configuración con KICS<br/>
        <b>Total de Hallazgos:</b> {self.stats['total']}<br/>
        <b>Plataformas Analizadas:</b> {', '.join(self.stats['by_platform'].keys())}<br/>
        <br/>
        <b>Distribución por Severidad:</b><br/>
        • <font color='#c0392b'><b>Críticas:</b></font> {self.stats['critical']} hallazgos<br/>
        • <font color='#e74c3c'><b>Altas:</b></font> {self.stats['high']} hallazgos<br/>
        • <font color='#f39c12'><b>Medias:</b></font> {self.stats['medium']} hallazgos<br/>
        • <font color='#f1c40f'><b>Bajas:</b></font> {self.stats['low']} hallazgos<br/>
        • <font color='#3498db'><b>Informativas:</b></font> {self.stats['info']} hallazgos<br/>
        """
        elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
        
        return elements

    def create_statistics_section(self):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("ESTADÍSTICAS DETALLADAS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        severity_data = [['Severidad', 'Cantidad', 'Porcentaje']]
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = self.stats['by_severity'].get(severity, 0)
            percentage = (count / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
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
        
        elements.append(Paragraph("PRINCIPALES CATEGORÍAS DE HALLAZGOS", self.styles['Heading3']))
        elements.append(Spacer(1, 0.1*inch))
        
        sorted_categories = sorted(self.stats['by_category'].items(), key=lambda x: x[1], reverse=True)[:10]
        category_data = [['Categoría', 'Cantidad']]
        for category, count in sorted_categories:
            category_data.append([category[:50], str(count)])
        
        category_table = Table(category_data, colWidths=[3.5*inch, 1.5*inch])
        category_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        
        elements.append(category_table)
        return elements

    def create_findings_section(self):
        elements = []
        vulnerabilities_by_severity = defaultdict(list)
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            vulnerabilities_by_severity[severity].append(vuln)
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        for severity in severity_order:
            vulns = vulnerabilities_by_severity.get(severity, [])
            if not vulns:
                continue
            
            elements.append(PageBreak())
            elements.append(Paragraph(f"HALLAZGOS {severity} ({len(vulns)})", self.styles['CustomHeading2']))
            elements.append(Spacer(1, 0.2*inch))
            
            for idx, vuln in enumerate(vulns, 1):
                if idx > 1:
                    elements.append(Spacer(1, 0.2*inch))
                
                elements.append(Paragraph(f"<b>{idx}. {vuln.get('queryName', 'Sin título')[:80]}</b>", self.styles['Heading3']))
                
                details = f"""
                <b>Archivo:</b> {vuln.get('file', 'Archivo desconocido')}<br/>
                <b>Línea:</b> {vuln.get('line', 'N/A')}<br/>
                <b>Categoría:</b> {vuln.get('category', 'N/A')}<br/>
                <b>Descripción:</b> {vuln.get('description', 'Sin descripción')[:200]}...<br/>
                """
                elements.append(Paragraph(details, self.styles['BodyText']))
                
                value = vuln.get('value', '')
                if value:
                    elements.append(Spacer(1, 0.05*inch))
                    elements.append(Paragraph("<b>Fragmento de Configuración:</b>", self.styles['Normal']))
                    elements.append(Preformatted(str(value)[:300], self.styles['Normal']))
        
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
                title='Reporte de Análisis KICS'
            )
            
            elements = []
            
            elements.append(Spacer(1, 1*inch))
            elements.append(Paragraph("REPORTE DE ANÁLISIS DE SEGURIDAD", self.styles['CustomTitle']))
            elements.append(Paragraph("Análisis de Configuración con KICS", self.styles['Heading2']))
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
            print(f"✓ PDF generado exitosamente: {self.pdf_output_path}")
            
        except Exception as e:
            print(f"✗ Error al generar PDF: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    
    json_report = sys.argv[1]
    output_pdf = sys.argv[2]
    logo = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"
    
    generator = KICSReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()

if __name__ == '__main__':
    main()