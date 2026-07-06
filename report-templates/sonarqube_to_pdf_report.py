#!/usr/bin/env python3
"""
Script para convertir resultados de la API de SonarQube a PDF estructurado institucional
Uso: python3 sonarqube_to_pdf_report.py <url> <token> <project_key> <output_pdf> [logo_path]
"""

import json
import sys
import os
import html
import urllib.request
import base64
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib import colors

class SonarQubeReportGenerator:
    def __init__(self, sonar_url, sonar_token, project_key, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.sonar_url = sonar_url.rstrip('/')
        self.sonar_token = sonar_token
        self.project_key = project_key
        self.pdf_output_path = pdf_output_path
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)
        
        self.test_type = "DevSecOps-Sonar"  
        self.metrics = {}
        self.issues = []
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

    def _make_api_request(self, endpoint):
        """Helper para consultas a la API de SonarQube"""
        url = f"{self.sonar_url}{endpoint}"
        auth = base64.b64encode(f"{self.sonar_token}:".encode('utf-8')).decode('utf-8')
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {auth}")
        try:
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as e:
            print(f"✗ Error API SonarQube ({endpoint}): {e}")
            return None

    def fetch_data(self):
            """Obtener datos reales desde el servidor de SonarQube con paginación ilimitada"""
            print(f"📡 Conectando a SonarQube en {self.sonar_url}...")
            
            metrics_keys = "alert_status,bugs,vulnerabilities,security_hotspots,code_smells,sqale_index"
            metrics_ep = f"/api/measures/component?component={self.project_key}&metricKeys={metrics_keys}"
            m_data = self._make_api_request(metrics_ep)
            
            if m_data and 'component' in m_data:
                for measure in m_data['component'].get('measures', []):
                    self.metrics[measure['metric']] = measure.get('value', '0')

            print("📥 Descargando todos los hallazgos (issues)...")
            self.issues = []
            page_index = 1
            page_size = 500
            
            while True:
                issues_ep = f"/api/issues/search?componentKeys={self.project_key}&resolved=false&ps={page_size}&p={page_index}&s=SEVERITY&asc=false"
                i_data = self._make_api_request(issues_ep)
                
                if not i_data or 'issues' not in i_data:
                    break
                    
                batch_issues = i_data['issues']
                self.issues.extend(batch_issues)
                
                if len(batch_issues) < page_size:
                    break
                    
                page_index += 1

            # ====================================================================
            # 3. NUEVO: Descargar Security Hotspots (Ruta API diferente)
            # ====================================================================
            print("📥 Descargando Security Hotspots...")
            page_index = 1
            
            while True:
                hotspots_ep = f"/api/hotspots/search?projectKey={self.project_key}&status=TO_REVIEW&ps={page_size}&p={page_index}"
                h_data = self._make_api_request(hotspots_ep)
                
                if not h_data or 'hotspots' not in h_data:
                    break
                    
                batch_hotspots = h_data['hotspots']
                
                for hotspot in batch_hotspots:
                    prob = hotspot.get('vulnerabilityProbability', 'UNKNOWN').upper()
                    self.issues.append({
                        'severity': prob, 
                        'type': 'SECURITY_HOTSPOT',
                        'component': hotspot.get('component', ''),
                        'message': hotspot.get('message', 'Revisión de seguridad requerida'),
                        'line': hotspot.get('line', 'N/A')
                    })
                    
                if len(batch_hotspots) < page_size:
                    break
                    
                page_index += 1
                
            print(f"✓ Datos recuperados: {len(self.issues)} problemas detectados en total (Issues + Hotspots)")

    def create_executive_summary(self):
        """Crear resumen ejecutivo"""
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO DE CALIDAD", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        status = self.metrics.get('alert_status', 'UNKNOWN')
        status_color = '#27ae60' if status == 'OK' else '#c0392b'
        
        display_status = "APROBADO" if status == 'OK' else "FALLIDO"
        
        debt_mins = int(self.metrics.get('sqale_index', 0))
        debt_str = f"{debt_mins // 60}h {debt_mins % 60}min" if debt_mins > 0 else "0min"

        summary_text = f"""
        <b>Proyecto Analizado:</b> {self.project_key}<br/>
        <b>Estado del Quality Gate:</b> <font color='{status_color}'><b>{display_status}</b></font><br/>
        <b>Deuda Técnica Estimada:</b> {debt_str}<br/>
        <br/>
        <b>Métricas de Salud del Código:</b><br/>
        • <font color='#e74c3c'><b>Bugs:</b></font> {self.metrics.get('bugs', 0)} hallazgos<br/>
        • <font color='#c0392b'><b>Vulnerabilidades:</b></font> {self.metrics.get('vulnerabilities', 0)} hallazgos<br/>
        • <font color='#f39c12'><b>Security Hotspots:</b></font> {self.metrics.get('security_hotspots', 0)} revisiones pendientes<br/>
        • <font color='#3498db'><b>Code Smells:</b></font> {self.metrics.get('code_smells', 0)} problemas de mantenibilidad<br/>
        """
        elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
        
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("ACCIONES RECOMENDADAS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        if status != 'OK':
            rec = "<b>⚠️ Acción Urgente:</b> El proyecto no ha superado el Quality Gate. Se debe priorizar la corrección de Vulnerabilidades y Bugs antes del siguiente paso a producción."
        else:
            rec = "<b>✅ Mantener Calidad:</b> El proyecto cumple los estándares actuales. Se recomienda abordar paulatinamente los Code Smells para reducir la deuda técnica a largo plazo."
            
        elements.append(Paragraph(rec, self.styles['BodyJustified']))
        return elements

    def create_issues_section(self):
        """Listado detallado de hallazgos de SonarQube"""
        elements = []
        if not self.issues:
            return elements

        elements.append(PageBreak())
        elements.append(Paragraph("DETALLE DE HALLAZGOS PRIORITARIOS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))

        for idx, issue in enumerate(self.issues, 1):
            severity = issue.get('severity', 'UNKNOWN')
            type_issue = issue.get('type', 'ISSUE')
            component = issue.get('component', '').split(':')[-1]
            msg = html.escape(issue.get('message', 'Sin descripción'))
            
            type_color = '#c0392b' if type_issue == 'VULNERABILITY' else '#2c3e50'

            elements.append(Paragraph(
                f"<b>{idx}. <font color='{type_color}'>{type_issue}</font> - {severity}</b>", 
                self.styles['Heading3']
            ))
            
            details = f"""
            <b>Archivo:</b> {component}<br/>
            <b>Mensaje:</b> {msg}<br/>
            <b>Línea:</b> {issue.get('line', 'N/A')}<br/>
            """
            elements.append(Paragraph(details, self.styles['BodyText']))
            elements.append(Spacer(1, 0.15*inch))
            
        return elements

    def generate_pdf(self):
        """Generar el documento final"""
        try:
            self.fetch_data()
            
            doc = SimpleDocTemplate(
                self.pdf_output_path,
                pagesize=letter,
                topMargin=100,    
                bottomMargin=50,  
                rightMargin=40,
                leftMargin=40,
                title=f"Reporte SonarQube - {self.project_key}"
            )
            
            elements = []
            
            
            elements.append(Spacer(1, 1*inch))
            elements.append(Paragraph("REPORTE DE CALIDAD Y ESTATISMO", self.styles['CustomTitle']))
            elements.append(Paragraph("Análisis SAST con SonarQube", self.styles['Heading2']))
            elements.append(Spacer(1, 0.5*inch))
            
            elements.append(Paragraph("TABLA DE CONTENIDOS", self.styles['CustomHeading2']))
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph("1. Resumen Ejecutivo", self.styles['Normal']))
            
            if self.issues:
                elements.append(Paragraph("2. Detalle de Hallazgos Prioritarios", self.styles['Normal']))
            
            elements.append(PageBreak())
            
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_issues_section())
            
            doc.build(elements, onFirstPage=self.draw_header, onLaterPages=self.draw_header)
            print(f"✓ PDF de SonarQube generado exitosamente: {self.pdf_output_path}")
            
        except Exception as e:
            print(f"✗ Error al generar PDF SonarQube: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) < 5:
        print("Uso: python3 sonarqube_to_pdf_report.py <url> <token> <project_key> <output_pdf>")
        sys.exit(1)
        
    sonar_url = sys.argv[1]
    sonar_token = sys.argv[2]
    project_key = sys.argv[3]
    output_pdf = sys.argv[4]
    logo = sys.argv[5] if len(sys.argv) > 5 else "Logo_Simon_Ultimo.png"
    
    generator = SonarQubeReportGenerator(sonar_url, sonar_token, project_key, output_pdf, logo)
    generator.generate_pdf()

if __name__ == '__main__':
    main()