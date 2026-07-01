#!/usr/bin/env python3
"""
Script para convertir reportes JSON de Gitleaks a PDF estructurado institucional.
Incluye manejo de desbordamiento de texto (textwrap) y estilos corporativos.
Uso: python3 gitleaks_to_pdf_report.py <json_report> <output_pdf> [logo_path]
"""

import json
import sys
import os
import html
import textwrap
from datetime import datetime
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Preformatted
)
from reportlab.lib import colors

class GitleaksReportGenerator:
    def __init__(self, json_report_path, pdf_output_path, logo_filename="Logo_Simon_Ultimo.png"):
        self.json_report_path = json_report_path
        self.pdf_output_path = pdf_output_path
        
        # Ruta absoluta para asegurar que siempre encuentre el logo
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(script_dir, logo_filename)
        
        self.test_type = "DevSecOps-Leaks"
        self.secrets = []
        self.stats = {}
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Definición de la paleta de colores y tipografía institucional"""
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


        self.styles.add(ParagraphStyle(
            name='SecretBox',
            parent=self.styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#c0392b'),
            fontName='Courier-Bold',
            backColor=colors.HexColor('#fadbd8'),
            borderPadding=6
        ))

        self.styles.add(ParagraphStyle(
            name='TableCellWrap',
            parent=self.styles['Normal'],
            fontSize=9,
            leading=11,
            alignment=TA_LEFT,
            textColor=colors.HexColor('#333333')
        ))

    def draw_header(self, canvas, doc):
        """Renderiza el logo, la tabla de clasificación y la línea divisoria"""
        canvas.saveState()
        width, height = letter
        
        if os.path.exists(self.logo_path):
            canvas.drawImage(self.logo_path, 40, height - 70, width=140, height=40, preserveAspectRatio=True, mask='auto')
        else:
            print(f"⚠️ ADVERTENCIA: No se encontró el logo en: {self.logo_path}")
            
        # 2. Cuadrícula de Metadatos (Derecha)
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
        """Carga el JSON y clasifica los secretos en Activos o Históricos (Ghost Leaks)"""
        try:
            with open(self.json_report_path, 'r', encoding='utf-8') as f:
                data = f.read()
                if not data.strip():
                    self.secrets = []
                else:
                    self.secrets = json.loads(data)
            
            workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            
            self.active_count = 0
            self.ghost_count = 0
            
            for secret in self.secrets:
                file_path = secret.get('File', '')
                match_str = secret.get('Match', '')
                target_file = os.path.join(workspace_root, file_path)
                
                is_ghost = True
                if os.path.exists(target_file):
                    try:
                        with open(target_file, 'r', encoding='utf-8', errors='ignore') as current_file:
                            if match_str in current_file.read():
                                is_ghost = False
                    except Exception:
                        pass 
                
                secret['IsGhost'] = is_ghost
                if is_ghost:
                    self.ghost_count += 1
                else:
                    self.active_count += 1
                    
            print(f"✓ Reporte Gitleaks cargado: {len(self.secrets)} secretos en total ({self.active_count} Activos, {self.ghost_count} Históricos/Ghost)")
            
        except FileNotFoundError:
            print(f"✗ Error crítico: Archivo {self.json_report_path} no encontrado.")
            sys.exit(1)
        except json.JSONDecodeError:
            print("✗ Error crítico: El archivo JSON de Gitleaks está corrupto o mal formado.")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Error inesperado al leer JSON: {str(e)}")
            sys.exit(1)

    def calculate_statistics(self):
        """Análisis profundo de los secretos para generar métricas"""
        rule_counts = defaultdict(int)
        file_counts = defaultdict(int)
        
        for secret in self.secrets:
            rule = secret.get('Description', 'Regla Desconocida')
            file_path = secret.get('File', 'Archivo desconocido')
            rule_counts[rule] += 1
            file_counts[file_path] += 1
        
        self.stats = {
            'total': len(self.secrets),
            'by_rule': dict(sorted(rule_counts.items(), key=lambda item: item[1], reverse=True)),
            'by_file': dict(sorted(file_counts.items(), key=lambda item: item[1], reverse=True)),
            'files_affected': len(file_counts)
        }

    def create_executive_summary(self):
        """Genera la sección de resumen con acciones recomendadas"""
        elements = []
        elements.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        if self.stats['total'] == 0:
            summary_text = """
            <b>Estado del Análisis:</b> <font color='#27ae60'><b>APROBADO</b></font><br/><br/>
            El escaneo de seguridad en busca de secretos expuestos ha concluido exitosamente. 
            No se han detectado credenciales, tokens, llaves privadas ni contraseñas hardcodeadas en el código fuente. 
            El proyecto cumple estrictamente con las políticas de cero secretos en el repositorio.
            """
            elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
            return elements

        summary_text = f"""
        <b>Estado del Análisis:</b> <font color='#c0392b'><b>FALLIDO</b></font><br/>
        <b>Total de Secretos Expuestos:</b> {self.stats['total']}<br/>
        <b>Archivos Comprometidos:</b> {self.stats['files_affected']}<br/><br/>
        La exposición de secretos en el control de versiones es una de las vulnerabilidades más críticas. 
        Cualquier actor con acceso de lectura al repositorio o a su historial podría extraer estas credenciales 
        y comprometer infraestructura interna, bases de datos o servicios en la nube.
        """
        elements.append(Paragraph(summary_text, self.styles['BodyJustified']))
        
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("PLAN DE REMEDIACIÓN INMEDIATA", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        recommendations = """
        <b>1. Revocación Obligatoria:</b> Considerar todas las credenciales listadas en este reporte como comprometidas. Deben ser revocadas en su origen (AWS, bases de datos, APIs de terceros) de manera inmediata.<br/>
        <b>2. Limpieza de Historial:</b> Eliminar el secreto del commit actual no es suficiente. Se debe utilizar <code>git filter-repo</code> para purgar la credencial de todo el historial de Git.<br/>
        <b>3. Inyección Segura:</b> Implementar el uso de variables de entorno, Azure Key Vault o AWS Secrets Manager para inyectar estos valores en tiempo de despliegue.
        """
        elements.append(Paragraph(recommendations, self.styles['BodyJustified']))
        
        return elements

    def create_statistics_section(self):
        """Tablas estadísticas con cálculo de porcentajes y WrapText"""
        elements = []
        if self.stats['total'] == 0:
            return elements

        elements.append(PageBreak())
        elements.append(Paragraph("ESTADÍSTICAS DETALLADAS", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        elements.append(Paragraph("TIPOS DE SECRETOS DETECTADOS", self.styles['Heading3']))
        elements.append(Spacer(1, 0.1*inch))
        
        rule_data = [['Tipo de Secreto / Regla', 'Cantidad', 'Impacto (%)']]
        for rule, count in list(self.stats['by_rule'].items())[:15]:
            percentage = (count / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
            p_rule = Paragraph(html.escape(rule), self.styles['TableCellWrap'])
            rule_data.append([p_rule, str(count), f'{percentage:.1f}%'])
        
        rule_table = Table(rule_data, colWidths=[4.0*inch, 1.0*inch, 1.0*inch])
        rule_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        
        elements.append(rule_table)
        elements.append(Spacer(1, 0.3*inch))

        elements.append(Paragraph("TOP ARCHIVOS COMPROMETIDOS", self.styles['Heading3']))
        elements.append(Spacer(1, 0.1*inch))
        
        file_data = [['Ruta del Archivo', 'Secretos']]
        for file_path, count in list(self.stats['by_file'].items())[:15]:
            p_file = Paragraph(html.escape(file_path), self.styles['TableCellWrap'])
            file_data.append([p_file, str(count)])
        
        file_table = Table(file_data, colWidths=[5.0*inch, 1.0*inch])
        file_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        
        elements.append(file_table)
        return elements

    def create_findings_section(self):
        """Listado detallado de los secretos con corrección de margen"""
        elements = []
        if self.stats['total'] == 0:
            return elements

        elements.append(PageBreak())
        title = f"DETALLE DE HALLAZGOS CRÍTICOS ({self.stats['total']})"
        elements.append(Paragraph(title, self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        for idx, secret in enumerate(self.secrets, 1):
            if idx > 1:
                elements.append(Spacer(1, 0.25*inch))
            
            rule = html.escape(str(secret.get('Description', 'Regla Desconocida')))
            file_path = html.escape(str(secret.get('File', 'Archivo desconocido')))
            line = str(secret.get('StartLine', 'N/A'))
            
            raw_author = secret.get('Author', '').strip()
            author = html.escape(raw_author) if raw_author else 'No disponible (--no-git)'
            
            raw_commit = secret.get('Commit', '').strip()
            commit = html.escape(raw_commit[:8]) if raw_commit else 'N/A'
            
            is_ghost = secret.get('IsGhost', False)
            if is_ghost:
                ghost_badge = "<font color='#f39c12'><i>[Histórico / Ghost Leak]</i></font>"
            else:
                ghost_badge = "<font color='#c0392b'><b>[Activo en Código]</b></font>"
            
            elements.append(Paragraph(f"<b>{idx}. {rule}</b> {ghost_badge}", self.styles['Heading3']))
            
            details = f"""
            <b>Archivo Afectado:</b> {file_path}<br/>
            <b>Línea:</b> {line} | <b>Commit:</b> {commit} | <b>Autor:</b> {author}<br/>
            """
            elements.append(Paragraph(details, self.styles['BodyText']))
            elements.append(Spacer(1, 0.05*inch))
            
            raw_match = str(secret.get('Match', 'No se pudo extraer el string'))
            safe_match = raw_match.replace('<', '&lt;').replace('>', '&gt;')
            wrapped_match = textwrap.fill(safe_match, width=80, break_long_words=True, break_on_hyphens=True)
            
            elements.append(Paragraph("<b>Fragmento Expuesto Detectado:</b>", self.styles['Normal']))
            elements.append(Preformatted(wrapped_match, self.styles['SecretBox']))
             
        return elements

    def generate_pdf(self):
        """Construcción y orquestación final del documento"""
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
                title='Reporte de Secretos - DevSecOps'
            )
            
            elements = []
            
            elements.append(Spacer(1, 1*inch))
            elements.append(Paragraph("REPORTE DE DETECCIÓN DE SECRETOS", self.styles['CustomTitle']))
            elements.append(Paragraph("Análisis Estático con Gitleaks", self.styles['Heading2']))
            elements.append(Spacer(1, 0.5*inch))
            
            elements.append(Paragraph("TABLA DE CONTENIDOS", self.styles['CustomHeading2']))
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph("1. Resumen Ejecutivo", self.styles['Normal']))
            if self.stats['total'] > 0:
                elements.append(Paragraph("2. Estadísticas Detalladas", self.styles['Normal']))
                elements.append(Paragraph("3. Detalle de Hallazgos Críticos", self.styles['Normal']))
            
            elements.append(PageBreak())
            
            elements.extend(self.create_executive_summary())
            elements.extend(self.create_statistics_section())
            elements.extend(self.create_findings_section())
            
            doc.build(elements, onFirstPage=self.draw_header, onLaterPages=self.draw_header)
            print(f"✓ PDF generado exitosamente y guardado en: {self.pdf_output_path}")
            
        except Exception as e:
            print(f"✗ Error al generar PDF: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Uso incorrecto. Faltan argumentos.")
        sys.exit(1)
    
    json_report = sys.argv[1]
    output_pdf = sys.argv[2]
    logo = sys.argv[3] if len(sys.argv) > 3 else "Logo_Simon_Ultimo.png"
    
    generator = GitleaksReportGenerator(json_report, output_pdf, logo)
    generator.generate_pdf()

if __name__ == '__main__':
    main()