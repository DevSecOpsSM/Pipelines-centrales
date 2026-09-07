#!/usr/bin/env python3
"""
Módulo común de branding para los reportes PDF DevSecOps.

Provee:
- Tokens de color y tipografía del branding Ciberseguridad (Template_SM_Ciber).
- Función `build_styles()` para construir los estilos ReportLab compartidos.
- Función `page_decorations_factory()` para producir el callback onPage con
  marca de agua (escudo Ss.png), encabezado (logo Simón + metadatos + línea
  teal) y pie (paginación).
- Función `tabla_distribucion_severidad()` que arma la tabla estándar
  Severidad / Cantidad / % con encabezado dark, filas alternas y TOTAL.

Todos los generadores individuales (`*_to_pdf_report.py`) importan de aquí
para compartir branding y evitar duplicación.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Callable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, StyleSheet1, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle


# ---------------------------------------------------------------------------
# Tokens de color (Template_SM_Ciber) — confirmados contra el docx oficial
# ---------------------------------------------------------------------------
TEAL = colors.HexColor("#00CCAF")           # Acento principal (títulos H2, líneas)
TEAL_DARK = colors.HexColor("#00806D")      # Teal oscurecido (bordes, hover)
TEAL_LIGHT = colors.HexColor("#5CD2C1")     # Teal claro (acentos suaves)
DARK = colors.HexColor("#1F2A36")           # Títulos, encabezado de tabla
GRAY_TEXT = colors.HexColor("#6B7280")      # Texto secundario
GRAY_BORDER = colors.HexColor("#E5E7EB")    # Bordes de tabla
ROW_ALT = colors.HexColor("#F3F6F5")        # Fila alterna / fondos suaves
GREEN_OK = colors.HexColor("#26C130")       # Éxito / OK
YELLOW = colors.HexColor("#FAD900")         # Warning / Medio
ORANGE = colors.HexColor("#FE7C43")         # Alto
RED = colors.HexColor("#E31952")            # Extremo / Crítico
BODY_TEXT = colors.HexColor("#1F2A36")      # Cuerpo de texto principal

# Colores por severidad para badges y stats
SEVERITY_COLORS = {
    "CRÍTICA": RED,
    "ALTA": ORANGE,
    "MEDIA": YELLOW,
    "BAJA": GREEN_OK,
}

# Constantes reusables
CLASIFICACION = "Confidencial"
FONT_SANS = "Helvetica"
FONT_SANS_BOLD = "Helvetica-Bold"
FONT_MONO = "Courier"

# Ruta del directorio de assets (image/) relativo al repo
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGE_DIR = os.path.abspath(os.path.join(_SCRIPT_DIR, os.pardir, "image"))

LOGO_SIMON = os.path.join(IMAGE_DIR, "Logo_Simon_Ultimo.png")
WATERMARK_SHIELD = os.path.join(IMAGE_DIR, "Ss.png")


# ---------------------------------------------------------------------------
# Estilos de párrafo compartidos
# ---------------------------------------------------------------------------
def build_styles() -> StyleSheet1:
    """
    Devuelve un StyleSheet ReportLab con los estilos del branding
    Template_SM_Ciber. Se agregan al stylesheet base y se sobrescribe
    Heading3 y Normal para mantener consistencia tipográfica.
    """
    styles = getSampleStyleSheet()

    # Título de portada (grande, dark, centrado)
    styles.add(ParagraphStyle(
        name="CustomTitle",
        parent=styles["Heading1"],
        fontSize=26,
        textColor=DARK,
        spaceAfter=18,
        alignment=TA_CENTER,
        fontName=FONT_SANS_BOLD,
        leading=32,
    ))

    # Subtítulo bajo el título de portada
    styles.add(ParagraphStyle(
        name="CustomSubtitle",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=GRAY_TEXT,
        alignment=TA_CENTER,
        fontName=FONT_SANS,
        spaceAfter=24,
        leading=16,
    ))

    # H2 de sección: color teal, línea inferior teal
    styles.add(ParagraphStyle(
        name="CustomHeading2",
        parent=styles["Heading2"],
        fontSize=15,
        textColor=TEAL,
        spaceAfter=14,
        spaceBefore=14,
        fontName=FONT_SANS_BOLD,
        borderColor=TEAL,
        borderWidth=0,
        borderPadding=(0, 0, 4, 0),
        underlineColor=TEAL,
        leading=18,
    ))

    # H3 de subsección: dark, sin borde
    styles.add(ParagraphStyle(
        name="CustomHeading3",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=DARK,
        spaceAfter=8,
        spaceBefore=10,
        fontName=FONT_SANS_BOLD,
        leading=15,
    ))

    # Cuerpo justificado
    styles.add(ParagraphStyle(
        name="BodyJustified",
        parent=styles["BodyText"],
        alignment=TA_JUSTIFY,
        fontSize=10,
        leading=13,
        textColor=BODY_TEXT,
        spaceAfter=8,
    ))

    # Texto pequeño gris (captions, notas)
    styles.add(ParagraphStyle(
        name="Caption",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=10,
        textColor=GRAY_TEXT,
        alignment=TA_LEFT,
    ))

    # Código / valores mono
    styles.add(ParagraphStyle(
        name="Mono",
        parent=styles["BodyText"],
        fontSize=9,
        leading=11,
        textColor=BODY_TEXT,
        fontName=FONT_MONO,
        backColor=ROW_ALT,
        borderPadding=4,
    ))

    return styles


# ---------------------------------------------------------------------------
# Encabezado, pie y marca de agua (callback onPage)
# ---------------------------------------------------------------------------
def page_decorations_factory(
    report_title: str,
    codigo: str,
    logo_path: str | None = None,
    watermark_path: str | None = None,
) -> Callable:
    """
    Fábrica que produce el callback onPage con:
    - Marca de agua central tenue (escudo Ss.png).
    - Encabezado: logo Simón a la izquierda, metadatos (código, vigencia,
      clasificación) a la derecha, línea teal inferior.
    - Pie: 'Confidencial · Página X' centrado.

    Parámetros:
        report_title: título del reporte (aparece en el encabezado a la derecha).
        codigo: código institucional del reporte (ej. 'DevSecOps-CHECKOV').
        logo_path: ruta al logo Simón. Si None, usa LOGO_SIMON por defecto.
        watermark_path: ruta al escudo. Si None, usa WATERMARK_SHIELD.
    """
    _logo = logo_path or LOGO_SIMON
    _watermark = watermark_path or WATERMARK_SHIELD
    _fecha = datetime.now().strftime("%d/%m/%Y")

    def _draw(canvas, doc):
        width, height = letter
        canvas.saveState()

        # --- Marca de agua central ---
        if _watermark and os.path.exists(_watermark):
            try:
                canvas.saveState()
                canvas.setFillAlpha(0.06)
                canvas.setStrokeAlpha(0.06)
                wm_size = 4.5 * inch
                canvas.drawImage(
                    _watermark,
                    (width - wm_size) / 2.0,
                    (height - wm_size) / 2.0,
                    width=wm_size,
                    height=wm_size,
                    preserveAspectRatio=True,
                    mask="auto",
                )
                canvas.restoreState()
            except Exception:
                canvas.restoreState()

        # --- Encabezado: logo izquierda ---
        if _logo and os.path.exists(_logo):
            canvas.drawImage(
                _logo,
                40,
                height - 62,
                width=110,
                height=32,
                preserveAspectRatio=True,
                mask="auto",
            )

        # --- Encabezado: metadatos derecha ---
        canvas.setFont(FONT_SANS_BOLD, 9)
        canvas.setFillColor(DARK)
        canvas.drawRightString(width - 40, height - 38, report_title)

        canvas.setFont(FONT_SANS, 8)
        canvas.setFillColor(GRAY_TEXT)
        meta_line = f"{codigo} · {CLASIFICACION} · {_fecha}"
        canvas.drawRightString(width - 40, height - 52, meta_line)

        # --- Línea teal inferior del encabezado ---
        canvas.setStrokeColor(TEAL)
        canvas.setLineWidth(1.5)
        canvas.line(40, height - 72, width - 40, height - 72)

        # --- Pie: línea teal fina + paginación centrada ---
        canvas.setStrokeColor(TEAL)
        canvas.setLineWidth(0.75)
        canvas.line(40, 42, width - 40, 42)

        canvas.setFont(FONT_SANS, 8)
        canvas.setFillColor(GRAY_TEXT)
        canvas.drawCentredString(
            width / 2.0,
            28,
            f"{CLASIFICACION} · Página {canvas.getPageNumber()}",
        )

        canvas.restoreState()

    return _draw


# ---------------------------------------------------------------------------
# Tabla estándar: Distribución por severidad
# ---------------------------------------------------------------------------
# Orden canónico de severidades (aparece siempre igual en todos los reportes)
SEVERITY_ORDER = ("CRÍTICA", "ALTA", "MEDIA", "BAJA")


def tabla_distribucion_severidad(
    stats: dict,
    total: int | None = None,
    incluir_ceros: bool = False,
) -> Table:
    """
    Construye la tabla estándar 'Distribución por severidad' que aparece en
    todos los reportes justo tras el resumen ejecutivo.

    Formato:
        | Severidad | Cantidad |    %   |
        | CRÍTICA   |    n     |  x.x % |
        | ALTA      |    n     |  x.x % |
        | MEDIA     |    n     |  x.x % |
        | BAJA      |    n     |  x.x % |
        | TOTAL     |    N     | 100 %  |

    Parámetros:
        stats: dict con al menos las claves 'critical', 'high', 'medium', 'low'.
        total: total de hallazgos. Si None, se calcula como la suma de los 4.
        incluir_ceros: si False (default), oculta filas con cantidad == 0.

    Devuelve un objeto Table listo para agregar al flujo de elementos.
    """
    key_map = {
        "CRÍTICA": "critical",
        "ALTA": "high",
        "MEDIA": "medium",
        "BAJA": "low",
    }

    counts = {sev: int(stats.get(key_map[sev], 0) or 0) for sev in SEVERITY_ORDER}
    computed_total = sum(counts.values())
    total_effective = int(total) if total is not None else computed_total

    data = [["Severidad", "Cantidad", "%"]]
    row_severities: list[str] = []

    for sev in SEVERITY_ORDER:
        cnt = counts[sev]
        if cnt == 0 and not incluir_ceros:
            continue
        pct = (cnt / total_effective * 100.0) if total_effective > 0 else 0.0
        data.append([sev, str(cnt), f"{pct:.1f} %"])
        row_severities.append(sev)

    # Fila TOTAL (siempre presente)
    data.append(["TOTAL", str(total_effective), "100 %" if total_effective > 0 else "0 %"])

    tabla = Table(data, colWidths=[2.4 * inch, 1.3 * inch, 1.3 * inch], hAlign="LEFT")

    style = [
        # Encabezado dark
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), FONT_SANS_BOLD),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 9),
        ("TOPPADDING", (0, 0), (-1, 0), 9),
        # Cuerpo
        ("FONTNAME", (0, 1), (-1, -2), FONT_SANS),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("TEXTCOLOR", (0, 1), (-1, -2), BODY_TEXT),
        ("ALIGN", (0, 1), (0, -1), "LEFT"),
        ("LEFTPADDING", (0, 1), (0, -1), 12),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
        # Filas alternas del cuerpo (excluye header y total)
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, ROW_ALT]),
        # Fila TOTAL
        ("BACKGROUND", (0, -1), (-1, -1), TEAL),
        ("TEXTCOLOR", (0, -1), (-1, -1), colors.white),
        ("FONTNAME", (0, -1), (-1, -1), FONT_SANS_BOLD),
        # Bordes
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, TEAL_DARK),
        ("LINEABOVE", (0, -1), (-1, -1), 1.2, TEAL_DARK),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY_BORDER),
    ]

    # Pastilla de color en la primera columna, por severidad
    for idx, sev in enumerate(row_severities, start=1):
        style.append(("TEXTCOLOR", (0, idx), (0, idx), SEVERITY_COLORS[sev]))
        style.append(("FONTNAME", (0, idx), (0, idx), FONT_SANS_BOLD))

    tabla.setStyle(TableStyle(style))
    return tabla


# ---------------------------------------------------------------------------
# Helper: márgenes recomendados para SimpleDocTemplate
# ---------------------------------------------------------------------------
DOC_MARGINS = dict(
    topMargin=90,
    bottomMargin=55,
    leftMargin=45,
    rightMargin=45,
)
