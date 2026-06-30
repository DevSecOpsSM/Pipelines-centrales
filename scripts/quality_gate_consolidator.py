#!/usr/bin/env python3
"""
pipelines-centrales · Quality Gate Consolidator
================================================

Agrega los artifacts `qg-summary-*.json` que produce cada workflow
reutilizable `sec-*.yml`, aplica la tabla CVSSv3 oficial de SIMON
Cybersecurity y genera tres salidas:

  1. Markdown del comentario consolidado para el PR     (--comment-out)
  2. Markdown del GitHub Actions Step Summary           (--summary-out)
  3. JSON final con los counts agregados y la decisión  (--result-out)

Tabla CVSSv3 (umbrales acumulados entre TODAS las herramientas):

    Severidad           CVSSv3       SLA           Umbral de bloqueo
    ─────────────────── ──────────── ──────────── ──────────────────
    Critical            9.0-10.0     24h          > 0
    High                7.0-8.9      7 días       > 0
    Medium              4.0-6.9      30 días      > 0
    Low                 0.1-3.9      90 días      > 20
    Info                —            —            > 50

Exit codes:
    0  →  Pass — ningún umbral excedido
    1  →  Blocked — al menos un umbral excedido
    2  →  Internal error (input inválido, sin summaries, etc.)

Schema esperado de cada qg-summary-*.json:

    {
        "schema_version": "1.0",
        "workflow":              "sec-secrets",
        "workflow_display_name": "Secrets Detection",
        "stage_number":          2,
        "tools":                 ["gitleaks", "trufflehog"],
        "scan_status":           "completed" | "skipped" | "error",
        "scan_status_reason":    "<texto opcional>",
        "severity_counts": {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        },
        "top_findings": [
            {
                "tool":        "gitleaks",
                "severity":    "critical",
                "rule_id":     "aws-access-token",
                "location":    "src/config.py:42",
                "description": "AWS access token detected"
            }
        ],
        "workflow_blocked": true,
        "block_reason":     "3 secretos detectados"
    }
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path

# Forzar UTF-8 en stdout/stderr — runners Ubuntu ya son UTF-8 nativo, pero
# en Windows console (cp1252) los emojis y flechas Unicode crashearían.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

# ════════════════════════════════════════════════════════════════════════════
# Umbrales y configuración
# ════════════════════════════════════════════════════════════════════════════

# Tabla CVSSv3 oficial — orden importante (Critical primero para fail-fast)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

THRESHOLDS = {
    # severidad : (umbral_bloqueo, etiqueta_CVSS, SLA)
    "critical": (0, "9.0-10.0", "24h calendario"),
    "high":     (0, "7.0-8.9",  "7 días"),
    "medium":   (0, "4.0-6.9",  "30 días"),
    "low":      (20, "0.1-3.9", "90 días"),
    "info":     (50, "—",       "—"),
}

SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

SEV_LABEL = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
}

MAX_TOP_FINDINGS = 10
COMMENT_MARKER = "<!-- security-quality-gate -->"


# ════════════════════════════════════════════════════════════════════════════
# Carga y validación de summaries
# ════════════════════════════════════════════════════════════════════════════

def load_summaries(summaries_dir: Path) -> list[dict]:
    """Lee todos los qg-summary-*.json del directorio y los devuelve."""
    if not summaries_dir.exists():
        print(f"[ERROR] Directorio no existe: {summaries_dir}", file=sys.stderr)
        return []

    summaries = []
    for path in sorted(summaries_dir.rglob("qg-summary-*.json")):
        try:
            with path.open(encoding="utf-8") as fh:
                data = json.load(fh)
            data["_source_file"] = str(path)
            summaries.append(data)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] No se pudo leer {path}: {exc}", file=sys.stderr)
    return summaries


def normalize_counts(raw: dict | None) -> dict[str, int]:
    """Normaliza el bloque severity_counts garantizando todas las claves."""
    raw = raw or {}
    return {sev: int(raw.get(sev, 0) or 0) for sev in SEVERITY_ORDER}


def aggregate(summaries: list[dict]) -> dict:
    """Suma counts y consolida la decisión de pass/fail."""
    totals = {sev: 0 for sev in SEVERITY_ORDER}
    all_findings = []
    blocked_workflows = []
    any_completed = False
    any_error = False

    for s in summaries:
        counts = normalize_counts(s.get("severity_counts"))
        for sev in SEVERITY_ORDER:
            totals[sev] += counts[sev]

        status = s.get("scan_status", "completed")
        if status == "completed":
            any_completed = True
        elif status == "error":
            any_error = True

        if s.get("workflow_blocked"):
            blocked_workflows.append({
                "workflow": s.get("workflow", "?"),
                "reason":   s.get("block_reason", "—"),
            })

        for f in s.get("top_findings") or []:
            all_findings.append({
                "workflow": s.get("workflow", "?"),
                "tool":     f.get("tool", "?"),
                "severity": f.get("severity", "info"),
                "rule_id":  f.get("rule_id", "?"),
                "location": f.get("location", "—"),
                "description": f.get("description", "—"),
            })

    # Aplicar umbrales acumulados
    breached = []
    for sev in SEVERITY_ORDER:
        threshold, _cvss, _sla = THRESHOLDS[sev]
        if totals[sev] > threshold:
            breached.append({
                "severity":  sev,
                "count":     totals[sev],
                "threshold": threshold,
            })

    sev_order_key = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    all_findings.sort(key=lambda f: sev_order_key.get(f["severity"], 99))
    top_global = all_findings[:MAX_TOP_FINDINGS]

    blocked = bool(breached or blocked_workflows or any_error)

    return {
        "totals":              totals,
        "breached":            breached,
        "blocked_workflows":   blocked_workflows,
        "top_findings_global": top_global,
        "any_completed":       any_completed,
        "any_error":           any_error,
        "blocked":             blocked,
    }


# ════════════════════════════════════════════════════════════════════════════
# Generación de salidas
# ════════════════════════════════════════════════════════════════════════════

def severity_badge(sev: str, count: int) -> str:
    if count == 0:
        return "—"
    return f"{SEV_ICON[sev]} {count}"


def build_per_workflow_table(summaries: list[dict]) -> str:
    """Tabla por etapa con counts y estado."""
    rows = []
    for s in sorted(summaries, key=lambda x: x.get("stage_number", 99)):
        counts = normalize_counts(s.get("severity_counts"))
        status = s.get("scan_status", "completed")

        if status == "skipped":
            estado = f"⏭️ Skipped"
        elif status == "error":
            estado = "⚠️ Error"
        elif s.get("workflow_blocked"):
            estado = "❌ Bloqueado"
        else:
            estado = "✅ OK"

        stage  = s.get("stage_number", "?")
        name   = s.get("workflow_display_name", s.get("workflow", "?"))
        tools  = " · ".join(s.get("tools") or [])
        rows.append(
            f"| {stage} | {name} | {tools} | "
            f"{severity_badge('critical', counts['critical'])} | "
            f"{severity_badge('high',     counts['high'])} | "
            f"{severity_badge('medium',   counts['medium'])} | "
            f"{severity_badge('low',      counts['low'])} | "
            f"{severity_badge('info',     counts['info'])} | "
            f"{estado} |"
        )
    return "\n".join(rows)


def build_thresholds_table(totals: dict[str, int]) -> str:
    rows = []
    for sev in SEVERITY_ORDER:
        threshold, cvss, _sla = THRESHOLDS[sev]
        count = totals[sev]
        if threshold == 0:
            ok = count == 0
            rule = "> 0 bloquea"
        else:
            ok = count <= threshold
            rule = f"> {threshold} bloquea"
        estado = "✅" if ok else "❌"
        rows.append(
            f"| {SEV_ICON[sev]} {SEV_LABEL[sev]} ({cvss}) | "
            f"{count} | {rule} | {estado} |"
        )
    return "\n".join(rows)


def build_top_findings_table(top: list[dict]) -> str:
    if not top:
        return "_Sin hallazgos para mostrar._"
    rows = ["| # | Severidad | Workflow | Herramienta | Regla | Ubicación |",
            "|---|-----------|----------|-------------|-------|-----------|"]
    for i, f in enumerate(top, 1):
        sev = f.get("severity", "info")
        rows.append(
            f"| {i} | {SEV_ICON.get(sev, '⚪')} {SEV_LABEL.get(sev, sev)} | "
            f"`{f.get('workflow', '?')}` | {f.get('tool', '?')} | "
            f"`{f.get('rule_id', '?')}` | `{f.get('location', '—')}` |"
        )
    return "\n".join(rows)


def build_sla_table() -> str:
    return (
        "| Severidad | CVSSv3 | SLA de remediación |\n"
        "|-----------|--------|--------------------|\n"
        "| 🔴 Critical | 9.0-10.0 | 24h calendario |\n"
        "| 🟠 High     | 7.0-8.9  | 7 días |\n"
        "| 🟡 Medium   | 4.0-6.9  | 30 días |\n"
        "| 🔵 Low      | 0.1-3.9  | 90 días |\n"
        "| ⚪ Info     | —        | — |"
    )


def build_comment(
    summaries: list[dict],
    result: dict,
    repo: str,
    run_id: str,
    sha: str,
) -> str:
    """Construye el cuerpo Markdown del comentario consolidado del PR."""
    blocked = result["blocked"]
    icon = "❌" if blocked else "✅"
    estado = "BLOQUEADO" if blocked else "APROBADO"

    reason_lines = []
    for b in result["breached"]:
        sev = b["severity"]
        reason_lines.append(
            f"- {SEV_ICON[sev]} **{SEV_LABEL[sev]}**: "
            f"{b['count']} hallazgos (umbral: > {b['threshold']})"
        )
    for w in result["blocked_workflows"]:
        reason_lines.append(f"- ❌ `{w['workflow']}` — {w['reason']}")

    if result["any_error"]:
        reason_lines.append("- ⚠️ Uno o más workflows reportaron error de escaneo")

    reason_block = (
        "### Motivos del bloqueo\n\n" + "\n".join(reason_lines) + "\n"
        if reason_lines else ""
    )

    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"
    sha_short = sha[:7] if sha else "—"

    return f"""{COMMENT_MARKER}
## 🔒 SSDLC Security — Quality Gate

**Estado:** {icon} **{estado}**
**Repositorio:** `{repo}`
**Commit:** `{sha_short}`
**Run:** [#{run_id}]({run_url})

{reason_block}
### Resumen por etapa

| # | Etapa | Herramientas | 🔴 Crit | 🟠 High | 🟡 Med | 🔵 Low | ⚪ Info | Estado |
|---|-------|--------------|---------|---------|--------|--------|---------|--------|
{build_per_workflow_table(summaries)}

### Umbrales aplicados (CVSSv3 acumulado)

| Severidad | Hallazgos | Regla | OK |
|-----------|-----------|-------|----|
{build_thresholds_table(result['totals'])}

### Top {MAX_TOP_FINDINGS} hallazgos (peor severidad primero)

{build_top_findings_table(result['top_findings_global'])}

### SLA de remediación

{build_sla_table()}

---

📋 Reportes HTML completos → [pestaña Artifacts del run]({run_url})
📖 Detalle del Quality Gate → [README de pipelines-centrales](https://github.com/{repo.split('/')[0]}/pipelines-centrales#readme)

🛡️ _Generado por `pipelines-centrales` · Equipo Cybersecurity · SIMON Movilidad_
"""


def build_step_summary(
    summaries: list[dict],
    result: dict,
    repo: str,
    run_id: str,
) -> str:
    """Construye el contenido del GitHub Step Summary (sin el marker)."""
    blocked = result["blocked"]
    icon = "❌" if blocked else "✅"
    estado = "BLOQUEADO" if blocked else "APROBADO"

    return f"""## {icon} Quality Gate — {estado}

**Repo:** `{repo}` · **Run:** [#{run_id}](https://github.com/{repo}/actions/runs/{run_id})

### Resumen por etapa

| # | Etapa | Herramientas | 🔴 Crit | 🟠 High | 🟡 Med | 🔵 Low | ⚪ Info | Estado |
|---|-------|--------------|---------|---------|--------|--------|---------|--------|
{build_per_workflow_table(summaries)}

### Umbrales aplicados

| Severidad | Hallazgos | Regla | OK |
|-----------|-----------|-------|----|
{build_thresholds_table(result['totals'])}
"""


def build_final_json(
    summaries: list[dict],
    result: dict,
    repo: str,
    run_id: str,
    sha: str,
) -> dict:
    """Estructura del quality-gate-final.json (artifact)."""
    return {
        "schema_version": "1.0",
        "generated_at":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "repository":     repo,
        "run_id":         run_id,
        "commit_sha":     sha,
        "blocked":        result["blocked"],
        "totals":         result["totals"],
        "breached":       result["breached"],
        "blocked_workflows": result["blocked_workflows"],
        "summaries_consumed": [
            {
                "workflow": s.get("workflow"),
                "tools":    s.get("tools"),
                "status":   s.get("scan_status"),
                "counts":   normalize_counts(s.get("severity_counts")),
                "blocked":  bool(s.get("workflow_blocked")),
            }
            for s in summaries
        ],
        "top_findings_global": result["top_findings_global"],
    }


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Consolida qg-summary-*.json y aplica el Quality Gate CVSSv3.",
    )
    p.add_argument("--summaries-dir", required=True, type=Path,
                   help="Directorio con los archivos qg-summary-*.json")
    p.add_argument("--repo",   default=os.environ.get("GITHUB_REPOSITORY", "unknown/unknown"))
    p.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "0"))
    p.add_argument("--sha",    default=os.environ.get("GITHUB_SHA", ""))
    p.add_argument("--comment-out", type=Path,
                   help="Ruta donde escribir el Markdown del PR comment")
    p.add_argument("--summary-out", type=Path,
                   help="Ruta donde APPEND el contenido del Step Summary "
                        "(usualmente $GITHUB_STEP_SUMMARY)")
    p.add_argument("--result-out", type=Path,
                   help="Ruta donde escribir quality-gate-final.json")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    summaries = load_summaries(args.summaries_dir)
    if not summaries:
        print("[ERROR] No se encontró ningún qg-summary-*.json — "
              "¿se ejecutaron los workflows sec-*.yml?", file=sys.stderr)
        return 2

    print(f"[INFO] {len(summaries)} summary(ies) consumido(s):")
    for s in summaries:
        print(f"       · {s.get('workflow', '?'):<25} "
              f"status={s.get('scan_status', '?'):<10} "
              f"blocked={s.get('workflow_blocked', False)}")

    result = aggregate(summaries)

    if args.comment_out:
        args.comment_out.write_text(
            build_comment(summaries, result, args.repo, args.run_id, args.sha),
            encoding="utf-8",
        )
        print(f"[OK] Comment markdown → {args.comment_out}")

    if args.summary_out:
        with args.summary_out.open("a", encoding="utf-8") as fh:
            fh.write(build_step_summary(summaries, result, args.repo, args.run_id))
            fh.write("\n")
        print(f"[OK] Step summary → {args.summary_out}")

    if args.result_out:
        args.result_out.write_text(
            json.dumps(
                build_final_json(summaries, result, args.repo, args.run_id, args.sha),
                indent=2, ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        print(f"[OK] Final JSON → {args.result_out}")

    totals = result["totals"]
    print("\n[Quality Gate] Totales acumulados:")
    for sev in SEVERITY_ORDER:
        print(f"  {SEV_ICON[sev]} {SEV_LABEL[sev]:<8} {totals[sev]}")

    if result["blocked"]:
        print("\n[Quality Gate] ❌ BLOQUEADO")
        for b in result["breached"]:
            print(f"  - {b['severity']}: {b['count']} > {b['threshold']}")
        for w in result["blocked_workflows"]:
            print(f"  - workflow blocked: {w['workflow']} — {w['reason']}")
        return 1

    print("\n[Quality Gate] ✅ APROBADO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
