#!/usr/bin/env python3
"""
Script para convertir reportes JSON de Trivy a PDF estructurado institucional.
Sigue los lineamientos corporativos de DevSecOps (Idéntico a OWASP SCA).
Uso: python3 trivy_to_pdf_report.py <json_report> <output_pdf> [logo_path]
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

class TrivyReportGenerator:
    # 🌟 CONSTANTES PARA SEVERIDAD (Igual a OWASP y SonarQube) 🌟
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    def __init__(self, json_report_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)
        
        self.test_type = "DevSecOps-Trivy"
        self.data = None
        self.results = []
        self.stats = {}
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Mantiene la tipografía y paleta corporativa."""
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
            borderColor=colors.HexColor('#00e5bd'), # Cyan corporativo
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
        """Renderiza el membrete corporativo en cada página."""
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
        
        # Línea divisoria Cyan corporativa
        canvas.setStrokeColor(colors.HexColor('#00e5bd'))
        canvas.setLineWidth(1.5)
        canvas.line(40, height - 80, width - 40, height - 80)
        
        # Paginación
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.gray)
        canvas.drawCentredString(width / 2.0, 30, f"Página {canvas.getPageNumber()}")
        
        canvas.restoreState()

    def load_json_report(self):
        """Parseo adaptado a la estructura JSON de Trivy."""
        try:
            with open(self.json_report_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            # Trivy guarda todo dentro de la llave 'Results'
            self.results = self.data.get('Results', [])
            print("✓ Reporte Trivy cargado exitosamente.")
        except Exception as e:
            print(f"✗ Error al cargar JSON Trivy: {str(e)}")
            sys.exit(1)

    def map_trivy_severity(self, raw_severity):
        """Mapea las severidades de Trivy (CRITICAL, HIGH...) a nuestras constantes."""
        sev = raw_severity.upper()
        if sev == "CRITICAL": return self.SEV_CRITICA
        elif sev == "HIGH": return self.SEV_ALTA
        elif sev == "MEDIUM": return self.SEV_MEDIA
        else: return self.SEV_BAJA

    def calculate_statistics(self):
        """Extrae estadísticas globales a partir de los Results de Trivy."""
        total_vulns = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        vuln_by_lib = defaultdict(int)
        vulnerable_targets = 0
        
        for result in self.results:
            vulns = result.get('Vulnerabilities', [])
            if vulns:
                vulnerable_targets += 1
                
            for vuln in vulns:
                total_vulns += 1
                severity = self.map_trivy_severity(vuln.get('Severity', 'UNKNOWN'))
                
                if severity == self.SEV_CRITICA: critical_count += 1
                elif severity == self.SEV_ALTA: high_count += 1
                elif severity == self.SEV_MEDIA: medium_count += 1
                else: low_count += 1
                
                # Para Trivy, el PkgName es la librería
                pkg_name = vuln.get('PkgName', 'Desconocido')
                vuln_by_lib[pkg_name] += 1
        
        self.stats = {
            'total_targets': len(self.results),
            'vulnerable_targets': vulnerable_targets,
            'total_vulnerabilities': total_vulns,
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'vuln_by_lib': dict(sorted(vuln_by_lib.items(), key=lambda item: item[1], reverse=True))
        }

    def create_executive_summary(self):
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        # --- NUEVO BLOQUE DE ESTADO ESTRICTO ---
        # Modifica estos números (0) según la tolerancia que decidan aceptar en el futuro
        has_risk = (
            self.stats['critical'] > 0 or 
            self.stats['high'] > 0 or 
            self.stats['medium'] > 0 or 
            self.stats['low'] > 0
        )
        
        if not has_risk:
            status_html = "<font color='#27ae60'><b>APROBADO</b></font>"
            status_desc = "El análisis universal de Trivy no detectó vulnerabilidades de ningún nivel en el código, contenedores o librerías. Los artefactos evaluados son 100% seguros para su paso a producción."
        else:
            status_html = "<font color='#c0392b'><b>FALLIDO</b></font>"
            status_desc = "El motor de Trivy ha interceptado librerías o dependencias con vulnerabilidades conocidas. El proyecto no cumple el Quality Gate y requiere remediación según el detalle del reporte."

        summary_text = f"""
        <b>Estado del Análisis:</b> {status_html}<br/>
        {status_desc}<br/><br/>
        <b>Total de Archivos de Dependencias Analizados:</b> {self.stats['total_targets']}<br/>
        <b>Archivos con Vulnerabilidades:</b> {self.stats['vulnerable_targets']}<br/>
        <b>Total de Vulnerabilidades Encontradas:</b> {self.stats['total_vulnerabilities']}<br/>
        <br/>
        <b>Distribución por Severidad (Trivy DB):</b><br/>
        • <font color='#c0392b'><b>Críticas:</b></font> {self.stats['critical']} vulnerabilidades<br/>
        • <font color='#e74c3c'><b>Altas:</b></font> {self.stats['high']} vulnerabilidades<br/>
        • <font color='#f39c12'><b>Medias:</b></font> {self.stats['medium']} vulnerabilidades<br/>
        • <font color='#f1c40f'><b>Bajas/Info:</b></font> {self.stats['low']} vulnerabilidades<br/>
        """
        # ---------------------------------------
        elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
        
        return elements

    def create_statistics_section(self):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("ESTADÍSTICAS DETALLADAS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Tabla de Severidad
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
        
        # Tabla de Librerías más afectadas
        elements.append(Paragraph("DEPENDENCIAS MÁS VULNERABLES", self.styles['Heading3']))
        elements.append(Spacer(1, 0.1*inch))
        
        top_vulns = list(self.stats['vuln_by_lib'].items())[:15]
        
        if top_vulns:
            vuln_data = [['Librería', 'Vulnerabilidades']]
            for lib_name, count in top_vulns:
                vuln_data.append([lib_name[:50], str(count)])
            
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

    def _extract_vulns_by_severity(self):
        """Agrupa las dependencias por severidad incluyendo metadatos de Trivy."""
        vulns_by_severity = {self.SEV_CRITICA: [], self.SEV_ALTA: [], self.SEV_MEDIA: [], self.SEV_BAJA: []}
        
        for result in self.results:
            target_file = result.get('Target', 'Unknown File')
            for vuln in result.get('Vulnerabilities', []):
                severity = self.map_trivy_severity(vuln.get('Severity', 'UNKNOWN'))
                vuln['TargetFile'] = target_file
                vulns_by_severity[severity].append(vuln)
                
        return vulns_by_severity

    def _create_severity_block(self, severity, vulns):
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph(f"VULNERABILIDADES {severity} ({len(vulns)})", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        for idx, vuln in enumerate(vulns, 1):
            if idx > 1: elements.append(Spacer(1, 0.15*inch))
            
            # Mapeo de campos Trivy
            vuln_id = html.escape(str(vuln.get('VulnerabilityID', 'Sin ID')))
            pkg_name = html.escape(str(vuln.get('PkgName', 'N/A')))
            installed_ver = html.escape(str(vuln.get('InstalledVersion', 'Desconocida')))
            fixed_ver = html.escape(str(vuln.get('FixedVersion', 'No disponible')))
            target_file = html.escape(str(vuln.get('TargetFile', 'N/A')))
            desc = html.escape(str(vuln.get('Description') or vuln.get('Title') or 'Sin descripción'))
            
            elements.append(Paragraph(f"<b>{idx}. {vuln_id} - {pkg_name}</b>", self.styles['Heading3']))
            
            details = f"""
            <b>Archivo Afectado:</b> {target_file}<br/>
            <b>Librería:</b> {pkg_name} (Instalada: {installed_ver} | <b>Solución:</b> {fixed_ver})<br/>
            <b>Descripción:</b> {desc[:250]}...<br/>
            """
            
            # En Trivy, el enlace primario suele venir en PrimaryURL
            primary_url = vuln.get('PrimaryURL')
            if primary_url:
                details += f"<b>Referencia:</b> {html.escape(str(primary_url))}<br/>"
            
            elements.append(Paragraph(details, self.styles['BodyText']))
        
        return elements

    def create_findings_section(self):
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
                title='Reporte Trivy Security Scan'
            )
            
            elements = []
            
            elements.append(Spacer(1, 1*inch))
            elements.append(Paragraph("REPORTE DE ANÁLISIS DE DEPENDENCIAS", self.styles['CustomTitle']))
            elements.append(Paragraph("Trivy Universal Scanner - SCA", self.styles['Heading2']))
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
            print(f"✓ PDF Trivy generado exitosamente: {self.pdf_output_path}")
            
        except Exception as e:
            print(f"✗ Error al generar PDF Trivy: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    
    json_report = sys.argv[1]
    output_pdf = sys.argv[2]
    logo = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"
    
    generator = TrivyReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()

if __name__ == '__main__':
    main()