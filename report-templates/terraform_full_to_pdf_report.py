#!/usr/bin/env python3
"""
Generador PDF institucional para el análisis full de Terraform.
Consolida fmt + validate + tflint + Checkov en UN PDF.

Uso:
  python3 terraform_full_to_pdf_report.py <primary_json> <output_pdf> [logo_path]

<primary_json> debe apuntar a checkov-raw.json. El generador busca los otros
2 JSONs en el mismo directorio:
    - terraform-native-raw.json  (fmt + validate)
    - tflint-raw.json

Los JSONs ausentes se saltan silenciosamente.

Refactor: usa el branding común Template_SM_Ciber (branding_sm.py).
"""

import html
import json
import os
import sys
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from branding_sm import (
    DOC_MARGINS,
    build_styles,
    page_decorations_factory,
    status_html,
    styled_secondary_table,
    tabla_distribucion_severidad,
)


class TerraformFullReportGenerator:
    SEV_CRITICA = "CRÍTICA"
    SEV_ALTA = "ALTA"
    SEV_MEDIA = "MEDIA"
    SEV_BAJA = "BAJA"

    REPORT_TITLE = "Reporte Terraform Full · IaC Security"
    CODIGO = "DevSecOps-TERRAFORM-FULL"

    def __init__(self, primary_json_path, pdf_output_path, logo_filename=None):
        self.primary_json_path = primary_json_path
        self.pdf_output_path = pdf_output_path
        self.input_dir = os.path.dirname(os.path.abspath(primary_json_path))

        script_dir = os.path.dirname(os.path.abspath(__file__))
        if logo_filename:
            if os.path.isabs(logo_filename):
                self.logo_path = logo_filename
            else:
                candidate = os.path.join(script_dir, logo_filename)
                self.logo_path = candidate if os.path.exists(candidate) else logo_filename
        else:
            self.logo_path = None

        self.native = {}
        self.tflint = []
        self.checkov = []
        self.checkov_sin_severity = 0
        self.tools_present = []

        # Stats institucionales — 4 niveles + total
        self.stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

        self.styles = build_styles()

    def _page_callback(self):
        return page_decorations_factory(
            report_title=self.REPORT_TITLE,
            codigo=self.CODIGO,
            logo_path=self.logo_path,
        )

    # ------------------------------------------------------------------
    # Carga de JSONs (fmt+validate, tflint, checkov)
    # ------------------------------------------------------------------
    def _load_json(self, filename):
        path = os.path.join(self.input_dir, filename)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
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

    # ------------------------------------------------------------------
    # Cálculo de estadísticas consolidadas
    # ------------------------------------------------------------------
    def calculate_stats(self):
        # terraform-native (fmt + validate)
        if self.native:
            for entry in self.native.get("validate", {}).get("by_dir", []) or []:
                for diag in entry.get("diagnostics", []) or []:
                    sev = (diag.get("severity") or "info").lower()
                    if sev == "error":
                        self.stats["critical"] += 1
                    elif sev == "warning":
                        self.stats["low"] += 1
                    else:
                        self.stats["low"] += 1  # info → BAJA
            # unformatted → BAJA
            self.stats["low"] += len(
                self.native.get("fmt", {}).get("unformatted_files", []) or []
            )

        # tflint
        for it in self.tflint:
            sev = (it.get("rule", {}).get("severity") or "notice").lower()
            if sev == "error":
                self.stats["medium"] += 1
            elif sev == "warning":
                self.stats["low"] += 1
            else:
                self.stats["low"] += 1  # notice/info → BAJA

        # Checkov (convención "sin severity → ALTA")
        for c in self.checkov:
            raw = c.get("severity")
            if isinstance(raw, dict):
                raw = raw.get("value") or ""
            if not isinstance(raw, str) or not raw.strip():
                self.checkov_sin_severity += 1
                self.stats["high"] += 1
                continue
            sev = raw.upper()
            if "CRIT" in sev:
                self.stats["critical"] += 1
            elif "HIGH" in sev:
                self.stats["high"] += 1
            elif "MED" in sev:
                self.stats["medium"] += 1
            elif "LOW" in sev:
                self.stats["low"] += 1
            else:
                self.stats["high"] += 1

        self.stats["total"] = sum(
            self.stats[k] for k in ("critical", "high", "medium", "low")
        )

    # ------------------------------------------------------------------
    # Secciones del PDF
    # ------------------------------------------------------------------
    def _cover(self):
        return [Spacer(1, 1.4 * inch),
                Paragraph("REPORTE DE SEGURIDAD IaC", self.styles["CustomTitle"]),
                Paragraph("Terraform Full · fmt · validate · tflint · Checkov",
                          self.styles["CustomSubtitle"]),
                Spacer(1, 0.3 * inch),
                Paragraph(f"Generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                          self.styles["Caption"]),
                Spacer(1, 0.4 * inch)]

    def _toc(self):
        elements = [Paragraph("TABLA DE CONTENIDOS", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        for line in ["1. Resumen ejecutivo y distribución consolidada",
                     "2. Estadísticas por herramienta",
                     "3. terraform fmt + validate",
                     "4. tflint · linter",
                     "5. Checkov · seguridad IaC"]:
            elements.append(Paragraph(line, self.styles["BodyJustified"]))
        elements.append(PageBreak())
        return elements

    def _executive_summary(self):
        elements = [Paragraph("1. RESUMEN EJECUTIVO", self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        has_risk = (self.stats["critical"] > 0 or self.stats["high"] > 0
                    or self.stats["medium"] > 0)
        passed = not has_risk

        if passed:
            desc = ("El análisis integral de Terraform concluyó sin hallazgos bloqueantes. "
                    "Los controles nativos, el linter y el escáner de seguridad coinciden "
                    "en que la infraestructura declarada cumple los umbrales institucionales.")
        else:
            desc = ("El análisis detectó hallazgos que superan los umbrales institucionales "
                    "(CVSSv3). Es obligatorio remediar los niveles CRÍTICA, ALTA y MEDIA "
                    "antes de desplegar la infraestructura.")

        tools_str = ", ".join(self.tools_present) if self.tools_present else "N/A"
        summary = (
            f"<b>Estado del análisis:</b> {status_html(passed)}<br/>"
            f"{desc}<br/><br/>"
            f"<b>Herramientas ejecutadas:</b> {tools_str}<br/>"
            f"<b>Total de hallazgos:</b> {self.stats['total']}"
        )
        elements.append(Paragraph(summary, self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.2 * inch))

        if self.stats["total"] > 0:
            elements.append(Paragraph("Distribución consolidada por severidad",
                                      self.styles["CustomHeading3"]))
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(tabla_distribucion_severidad(
                self.stats, total=self.stats["total"]))
            elements.append(Spacer(1, 0.15 * inch))
            caption = (
                "Distribución consolidada de fmt + validate, tflint y Checkov. "
                "Los porcentajes se calculan sobre el total de hallazgos."
            )
            if self.checkov_sin_severity > 0:
                caption += (
                    f"<br/><b>Nota:</b> {self.checkov_sin_severity} hallazgos de Checkov "
                    "no traen severidad nativa (Checkov OSS no la expone); se clasifican "
                    "como <b>ALTA</b> por convención del equipo."
                )
            elements.append(Paragraph(caption, self.styles["Caption"]))
        return elements

    def _stats_table(self):
        elements = [PageBreak(),
                    Paragraph("2. ESTADÍSTICAS POR HERRAMIENTA",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        data = [["Herramienta", "Crítica", "Alta", "Media", "Baja", "Total"]]

        def _row(name, c, h, m, l):
            return [name, str(c), str(h), str(m), str(l), str(c + h + m + l)]

        # fmt + validate
        if self.native:
            unformatted = len(self.native.get("fmt", {}).get("unformatted_files", []) or [])
            v_err = sum(1 for e in self.native.get("validate", {}).get("by_dir", []) or []
                        for d in e.get("diagnostics", []) or []
                        if (d.get("severity") or "").lower() == "error")
            v_warn = sum(1 for e in self.native.get("validate", {}).get("by_dir", []) or []
                         for d in e.get("diagnostics", []) or []
                         if (d.get("severity") or "").lower() == "warning")
            v_info = sum(1 for e in self.native.get("validate", {}).get("by_dir", []) or []
                         for d in e.get("diagnostics", []) or []
                         if (d.get("severity") or "").lower() not in ("error", "warning"))
            data.append(_row("fmt + validate", v_err, 0, 0, v_warn + v_info + unformatted))

        # tflint
        if self.tflint:
            tf_err = sum(1 for it in self.tflint
                         if (it.get("rule", {}).get("severity") or "").lower() == "error")
            tf_w = sum(1 for it in self.tflint
                       if (it.get("rule", {}).get("severity") or "").lower() == "warning")
            tf_n = len(self.tflint) - tf_err - tf_w
            data.append(_row("tflint", 0, 0, tf_err, tf_w + tf_n))

        # Checkov
        if self.checkov:
            c_c = c_h = c_m = c_l = 0
            for x in self.checkov:
                raw = x.get("severity")
                if isinstance(raw, dict):
                    raw = raw.get("value") or ""
                if not isinstance(raw, str) or not raw.strip():
                    c_h += 1
                    continue
                sv = raw.upper()
                if "CRIT" in sv:
                    c_c += 1
                elif "HIGH" in sv:
                    c_h += 1
                elif "MED" in sv:
                    c_m += 1
                elif "LOW" in sv:
                    c_l += 1
                else:
                    c_h += 1
            data.append(_row("Checkov", c_c, c_h, c_m, c_l))

        # Total
        data.append(_row("TOTAL",
                         self.stats["critical"], self.stats["high"],
                         self.stats["medium"], self.stats["low"]))

        elements.append(styled_secondary_table(
            data,
            [2.0 * inch, 0.8 * inch, 0.8 * inch, 0.8 * inch, 0.8 * inch, 0.9 * inch],
        ))
        return elements

    def _section_terraform_native(self):
        if not self.native:
            return []
        elements = [PageBreak(),
                    Paragraph("3. terraform fmt + validate",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]

        unformatted = self.native.get("fmt", {}).get("unformatted_files", []) or []
        by_dir = self.native.get("validate", {}).get("by_dir", []) or []
        totals = self.native.get("validate", {}).get("totals", {}) or {}

        elements.append(Paragraph(
            f"<b>Archivos sin formato canónico:</b> {len(unformatted)}<br/>"
            f"<b>Errores de validate:</b> {totals.get('error_count', 0)}<br/>"
            f"<b>Warnings de validate:</b> {totals.get('warning_count', 0)}",
            self.styles["BodyJustified"],
        ))

        if unformatted:
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "<b>Archivos que requieren <font face='Courier'>terraform fmt</font>:</b>",
                self.styles["BodyJustified"]))
            for f in unformatted[:30]:
                elements.append(Paragraph(
                    f"• <font face='Courier'>{html.escape(f)}</font>",
                    self.styles["BodyJustified"]))
            if len(unformatted) > 30:
                elements.append(Paragraph(
                    f"<i>… y {len(unformatted) - 30} archivos más</i>",
                    self.styles["Caption"]))

        if any(entry.get("diagnostics") for entry in by_dir):
            elements.append(Spacer(1, 0.15 * inch))
            elements.append(Paragraph(
                "<b>Diagnósticos de <font face='Courier'>terraform validate</font>:</b>",
                self.styles["BodyJustified"]))
            for entry in by_dir:
                if not entry.get("diagnostics"):
                    continue
                elements.append(Paragraph(
                    f"<b>Directorio:</b> "
                    f"<font face='Courier'>{html.escape(entry.get('dir', '?'))}</font>",
                    self.styles["BodyJustified"]))
                for diag in entry.get("diagnostics", [])[:10]:
                    sev = (diag.get("severity") or "info").upper()
                    summary = html.escape(diag.get("summary", ""))
                    detail = html.escape(diag.get("detail", ""))[:250]
                    elements.append(Paragraph(
                        f"[{sev}] {summary} — <font color='#6B7280'>{detail}</font>",
                        self.styles["BodyJustified"]))
        return elements

    def _section_tflint(self):
        if not self.tflint:
            return []
        elements = [PageBreak(),
                    Paragraph("4. tflint · Terraform Linter",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        elements.append(Paragraph(
            f"<b>Total de issues:</b> {len(self.tflint)}",
            self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.12 * inch))

        sev_order = {"error": 0, "warning": 1, "notice": 2, "info": 3}
        issues_sorted = sorted(
            self.tflint,
            key=lambda x: sev_order.get(
                (x.get("rule", {}).get("severity") or "notice").lower(), 99),
        )

        for it in issues_sorted[:40]:
            rule = it.get("rule", {}) or {}
            sev = (rule.get("severity") or "notice").upper()
            name = html.escape(rule.get("name", "?"))
            msg = html.escape(it.get("message", ""))
            rng = it.get("range") or {}
            fname = html.escape(str(rng.get("filename", "?")))
            line = (rng.get("start") or {}).get("line", "?")
            d = html.escape(it.get("_dir", "?"))
            elements.append(Paragraph(
                f"<b>[{sev}] {name}</b><br/>"
                f"<font size='9' color='#6B7280'>{d} · {fname}:{line}</font><br/>{msg}",
                self.styles["BodyJustified"]))
            elements.append(Spacer(1, 0.06 * inch))

        if len(self.tflint) > 40:
            elements.append(Paragraph(
                f"<i>… y {len(self.tflint) - 40} issues más</i>",
                self.styles["Caption"]))
        return elements

    def _section_checkov(self):
        if not self.checkov:
            return []
        elements = [PageBreak(),
                    Paragraph("5. Checkov · Seguridad IaC",
                              self.styles["CustomHeading2"]),
                    Spacer(1, 0.15 * inch)]
        elements.append(Paragraph(
            f"<b>Total de checks fallidos:</b> {len(self.checkov)}",
            self.styles["BodyJustified"]))
        elements.append(Spacer(1, 0.12 * inch))

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        def _sev_key(check):
            raw = check.get("severity")
            if isinstance(raw, dict):
                raw = raw.get("value") or ""
            if not isinstance(raw, str) or not raw.strip():
                return sev_order["HIGH"]
            return sev_order.get(raw.upper(), 99)

        checks_sorted = sorted(self.checkov, key=_sev_key)
        for c in checks_sorted[:40]:
            raw = c.get("severity")
            if isinstance(raw, dict):
                raw = raw.get("value") or ""
            sev = raw.upper() if isinstance(raw, str) and raw.strip() else "HIGH (sin severity)"
            cid = html.escape(c.get("check_id", "?"))
            cname = html.escape(c.get("check_name", ""))[:130]
            resource = html.escape(c.get("resource", "?"))
            file_path = html.escape(c.get("file_path", "?"))
            rng = c.get("file_line_range", ["?", "?"])
            line_str = f"{rng[0]}-{rng[1]}" if isinstance(rng, list) and len(rng) == 2 else "?"
            elements.append(Paragraph(
                f"<b>[{sev}] {cid}</b> — {cname}<br/>"
                f"<font size='9' color='#6B7280'>{resource} · {file_path}:{line_str}</font>",
                self.styles["BodyJustified"]))
            elements.append(Spacer(1, 0.06 * inch))

        if len(self.checkov) > 40:
            elements.append(Paragraph(
                f"<i>… y {len(self.checkov) - 40} checks más</i>",
                self.styles["Caption"]))
        return elements

    def generate_pdf(self):
        try:
            self.load_all()
            self.calculate_stats()

            doc = SimpleDocTemplate(
                self.pdf_output_path, pagesize=letter,
                title=self.REPORT_TITLE, **DOC_MARGINS,
            )
            elements = []
            elements.extend(self._cover())
            elements.extend(self._toc())
            elements.extend(self._executive_summary())
            elements.extend(self._stats_table())
            elements.extend(self._section_terraform_native())
            elements.extend(self._section_tflint())
            elements.extend(self._section_checkov())

            page_cb = self._page_callback()
            doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
            print(f"✓ PDF Terraform Full generado exitosamente: {self.pdf_output_path}")
        except Exception as exc:
            print(f"✗ Error al generar PDF Terraform Full: {exc}")
            sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 terraform_full_to_pdf_report.py <primary_json> <output_pdf> "
              "[logo_path]")
        sys.exit(1)
    logo = sys.argv[3] if len(sys.argv) > 3 else None
    TerraformFullReportGenerator(sys.argv[1], sys.argv[2], logo).generate_pdf()


if __name__ == "__main__":
    main()
