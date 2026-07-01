#!/usr/bin/env python3
"""
Script para convertir reportes JSON de OWASP Dependency Check a PDF estructurado institucional
Uso: python3 owasp_to_pdf_report.py <json_report> <output_pdf> [logo_path]
"""

import json
import sys
import os
import html
from datetime import datetime
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib import colors

class OWASPReportGenerator:
    
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    def __init__(self, json_report_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)
        
        self.test_type = "DevSecOps-OWASP"
        self.data = None
        self.dependencies = []
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
        else:
            print(f"⚠️ ADVERTENCIA: No se encontró el logo en la ruta: {self.logo_path}")
            
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
            self.dependencies = self.data.get('dependencies', [])
            print(f"✓ Reporte cargado: {len(self.dependencies)} dependencias analizadas")
        except Exception as e:
            print(f"✗ Error al cargar JSON OWASP: {str(e)}")
            sys.exit(1)

    def calculate_statistics(self):
        total_vulns = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        vuln_by_cvss = defaultdict(int)
        
        for dep in self.dependencies:
            vulns = dep.get('vulnerabilities', [])
            for vuln in vulns:
                total_vulns += 1
                cvss = self._get_vuln_cvss(vuln)
                
                if cvss >= 9.0: critical_count += 1
                elif cvss >= 7.0: high_count += 1
                elif cvss >= 4.0: medium_count += 1
                elif cvss >= 0.1: low_count += 1
                
                vuln_by_cvss[int(cvss)] += 1
        
        self.stats = {
            'total_dependencies': len(self.dependencies),
            'vulnerable_dependencies': len([d for d in self.dependencies if d.get('vulnerabilities')]),
            'total_vulnerabilities': total_vulns,
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'vuln_by_cvss': dict(sorted(vuln_by_cvss.items(), reverse=True))
        }

    def get_cvss_severity(self, cvss_score):
        try:
            score = float(cvss_score)
            if score >= 9.0: return self.SEV_CRITICA
            elif score >= 7.0: return self.SEV_ALTA
            elif score >= 4.0: return self.SEV_MEDIA
            else: return self.SEV_BAJA
        except (ValueError, TypeError):
            return "DESCONOCIDA"

    def create_executive_summary(self):
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        has_risk = (
            self.stats['critical'] > 0 or 
            self.stats['high'] > 0 or 
            self.stats['medium'] > 0 or 
            self.stats['low'] > 0
        )
        
        if not has_risk:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = "El escaneo de dependencias (SCA) concluyó con éxito. No se detectaron librerías de terceros con vulnerabilidades conocidas (CVEs) de ningún nivel, asegurando la integridad de la cadena de suministro."
        else:
            status_html = "<font color='#c0392b'><b>FALLIDO</b></font>"
            status_desc = "Se han detectado dependencias con vulnerabilidades (CVEs) documentadas. Es crítico revisar y actualizar estas librerías a versiones parchadas, ya que introducen riesgos a la aplicación."

        summary_text = f"""
        <b>Estado del Análisis:</b> {status_html}<br/>
        {status_desc}<br/><br/>
        <b>Total de Dependencias Escaneadas:</b> {self.stats['total_dependencies']}<br/>
        <b>Dependencias Vulnerables:</b> {self.stats['vulnerable_dependencies']}<br/>
        <b>Total de Vulnerabilidades Encontradas:</b> {self.stats['total_vulnerabilities']}<br/>
        <br/>
        <b>Distribución por Severidad (CVSS):</b><br/>
        • <font color='#c0392b'><b>Críticas (≥9.0):</b></font> {self.stats['critical']} vulnerabilidades<br/>
        • <font color='#e74c3c'><b>Altas (≥7.0):</b></font> {self.stats['high']} vulnerabilidades<br/>
        • <font color='#f39c12'><b>Medias (≥4.0):</b></font> {self.stats['medium']} vulnerabilidades<br/>
        • <font color='#f1c40f'><b>Bajas (&lt;4.0):</b></font> {self.stats['low']} vulnerabilidades<br/>
        """
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
            percentage = (count / self.stats['total_vulnerabilities'] * 100) if self.stats['total_vulnerabilities'] > 0 else 0
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
        
        elements.append(Paragraph("DEPENDENCIAS MÁS VULNERABLES", self.styles['Heading3']))
        elements.append(Spacer(1, 0.1*inch))
        
        vuln_by_lib = []
        for dep in self.dependencies:
            if dep.get('vulnerabilities'):
                vuln_by_lib.append({
                    'name': dep.get('fileName', 'Unknown'),
                    'count': len(dep.get('vulnerabilities', []))
                })
        
        vuln_by_lib.sort(key=lambda x: x['count'], reverse=True)
        top_vulns = vuln_by_lib[:15]
        
        if top_vulns:
            vuln_data = [['Librería', 'Vulnerabilidades']]
            for item in top_vulns:
                vuln_data.append([item['name'][:50], str(item['count'])])
            
            vuln_table = Table(vuln_data, colWidths=[3.5*inch, 1.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            elements.append(vuln_table)
        
        return elements

    def _get_vuln_cvss(self, vuln):
        """Extrae el score CVSS de una vulnerabilidad."""
        if 'cvssv3' in vuln: return vuln['cvssv3'].get('baseScore', 0)
        if 'cvssv2' in vuln: return vuln['cvssv2'].get('score', 0)
        return 0

    def _extract_vulns_by_severity(self):
        """Agrupa las dependencias por severidad."""
        vulns_by_severity = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        for dep in self.dependencies:
            for vuln in dep.get('vulnerabilities', []):
                cvss = self._get_vuln_cvss(vuln)
                severity = self.get_cvss_severity(cvss)
                vuln['library'] = dep.get('fileName', 'Unknown')
                vulns_by_severity[severity].append(vuln)
        return vulns_by_severity

    def _format_references(self, vuln):
        """Formatea las referencias (URLs) a HTML seguro."""
        if not vuln.get('references'):
            return ""
        refs = []
        for r in vuln.get('references', [])[:2]:
            if isinstance(r, dict):
                if 'name' in r: refs.append(html.escape(str(r['name'])))
                elif 'url' in r: refs.append(html.escape(str(r['url'])))
            elif isinstance(r, str):
                refs.append(html.escape(str(r)))
        if refs:
            return f"<b>Referencias:</b> {', '.join(refs)}<br/>"
        return ""

    def _create_severity_block(self, severity, vulns):
        """Genera los párrafos PDF para un bloque específico de severidad."""
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph(f"VULNERABILIDADES {severity} ({len(vulns)})", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        for idx, vuln in enumerate(vulns, 1):
            if idx > 1: elements.append(Spacer(1, 0.15*inch))
            
            cvss = self._get_vuln_cvss(vuln)
            vuln_name = html.escape(str(vuln.get('name', 'Sin nombre')))
            lib_name = html.escape(str(vuln.get('library', 'N/A')))
            desc = html.escape(str(vuln.get('description') or 'Sin descripción'))
            
            elements.append(Paragraph(f"<b>{idx}. {vuln_name[:70]}</b>", self.styles['Heading3']))
            
            details = f"""
            <b>Librería Afectada:</b> {lib_name}<br/>
            <b>CVE:</b> {vuln_name}<br/>
            <b>CVSS Score:</b> {cvss}<br/>
            <b>Descripción:</b> {desc[:200]}...<br/>
            """
            details += self._format_references(vuln)
            
            elements.append(Paragraph(details, self.styles['BodyText']))
        
        return elements

    def create_findings_section(self):
        """Función principal refactorizada para armar el PDF de hallazgos."""
        elements = []
        vulns_by_severity = self._extract_vulns_by_severity()
        
        for severity in [self.SEV_CRITICA, self.SEV_ALTA, self.SEV_MEDIA]:
            vulns = vulns_by_severity[severity]
            if vulns:
                elements.extend(self._create_severity_block(severity, vulns))
                
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
                title='Reporte OWASP Dependency Check'
            )
            
            elements = []
            
            elements.append(Spacer(1, 1*inch))
            elements.append(Paragraph("REPORTE DE ANÁLISIS DE DEPENDENCIAS", self.styles['CustomTitle']))
            elements.append(Paragraph("OWASP Dependency Check - SCA", self.styles['Heading2']))
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
            print(f"✓ PDF OWASP generado exitosamente: {self.pdf_output_path}")
            
        except Exception as e:
            print(f"✗ Error al generar PDF: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    
    json_report = sys.argv[1]
    output_pdf = sys.argv[2]
    logo = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"
    
    generator = OWASPReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()

if __name__ == '__main__':
    main()