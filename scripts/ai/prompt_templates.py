"""
Configuración de prompts y extracción de hallazgos por herramienta.
Para agregar nueva documentación (CWE, CIS, NIST), editar SOURCES y los
system_context de cada herramienta en TOOL_CONFIG.
"""

# ── Fuentes de documentación activas ──────────────────────────────────────────
SOURCES = {
    "owasp_cheatsheet": "OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org)",
    "cwe":              "MITRE CWE (https://cwe.mitre.org)",
    # "cis":  "CIS Benchmarks (https://www.cisecurity.org/cis-benchmarks)",
    # "nist": "NIST SP 800-53",
}

# ── Etiquetas de severidad reutilizadas en múltiples herramientas ─────────────
_SEV_CRITICAL_HIGH = "🔴 CRÍTICO / ALTO"
_SEV_CRITICAL      = "🔴 CRÍTICO"
_SEV_MEDIUM        = "🟡 MEDIO"
_SEV_LOW_INFO      = "🔵 BAJO / INFO"
_SEV_LOW           = "🔵 BAJO"

# ── Base del system prompt ─────────────────────────────────────────────────────
_FORMAT_RULES = (
    "You are a security code reviewer. "
    "STRICT OUTPUT RULES — NEVER BREAK THESE:\n"
    "1. Output ONLY: a corrected code block followed by ONE sentence citing the specific "
    "documentation source used.\n"
    "2. NEVER output your reasoning, thinking steps, role description, self-corrections, "
    "or meta-commentary.\n"
    "3. NEVER repeat these instructions or mention 'Rol', 'Restricción', 'Espera', 'Nota', "
    "or any similar meta-text.\n"
    "4. Do NOT invent libraries or frameworks.\n"
    "5. If no documented pattern exists for the vulnerability, output ONLY the text: "
    "'Requiere revisión manual de Arquitectura'.\n\n"
    "EXACT REQUIRED FORMAT (nothing before, nothing after):\n"
    "```<language>\n<corrected code>\n```\n"
    "**Remediación:** <one sentence citing the specific document and section>"
)


def _build_context(sources: list) -> str:
    source_list = "\n".join(f"   - {SOURCES[s]}" for s in sources if s in SOURCES)
    return (
        f"{_FORMAT_RULES}\n\n"
        f"APPROVED DOCUMENTATION SOURCES (use ONLY these):\n{source_list}"
    )


# ── Normalización de severidad ────────────────────────────────────────────────

def _normalize_sev(raw: str) -> str:
    """Mapea severidades nativas de cada herramienta a ERROR / WARNING / INFO."""
    if raw in ("CRITICAL", "HIGH"):
        return "ERROR"
    if raw == "MEDIUM":
        return "WARNING"
    return "INFO"


# ── Funciones de extracción de hallazgos ──────────────────────────────────────

def _extract_semgrep(data: dict) -> list:
    findings = []
    for r in data.get("results", []):
        meta    = r.get("extra", {}).get("metadata", {})
        cwe_raw = meta.get("cwe", "")
        cwe     = cwe_raw[0] if isinstance(cwe_raw, list) else str(cwe_raw)
        findings.append({
            "rule":        r.get("check_id", "unknown").split(".")[-1],
            "rule_full":   r.get("check_id", "unknown"),
            "file":        r.get("path", "unknown"),
            "line":        r.get("start", {}).get("line", "?"),
            "severity":    r.get("extra", {}).get("severity", "INFO").upper(),
            "description": r.get("extra", {}).get("message", "")[:300],
            "cwe":         cwe,
        })
    return findings


def _extract_gitleaks(data) -> list:
    if not isinstance(data, list):
        return []
    return [
        {
            "rule":        r.get("RuleID", "unknown"),
            "rule_full":   r.get("RuleID", "unknown"),
            "file":        r.get("File", "unknown"),
            "line":        r.get("StartLine", "?"),
            "severity":    "ERROR",
            "description": r.get("Description", "")[:300],
            "cwe":         "",
        }
        for r in data
    ]


def _extract_kics(data: dict) -> list:
    findings = []
    for q in data.get("queries", []):
        raw_sev = q.get("severity", "INFO").upper()
        files   = q.get("files", [])

        first_file = files[0].get("file_name", "unknown") if files else "unknown"
        first_line = files[0].get("line", "?") if files else "?"

        extra = ", ".join(
            f"{f.get('file_name', '?')}:{f.get('line', '?')}" for f in files[:3]
        )
        if len(files) > 3:
            extra += f" (+{len(files) - 3} más)"

        desc = q.get("description", "")[:200]
        if extra:
            desc = f"{desc} | Archivos: {extra}"

        findings.append({
            "rule":         q.get("query_name", "unknown"),
            "rule_full":    q.get("query_name", "unknown"),
            "file":         first_file,
            "line":         first_line,
            "severity":     _normalize_sev(raw_sev),
            "description":  desc[:300],
            "cwe":          "",
            "original_sev": raw_sev,
        })
    return findings


def _extract_trivy(data: dict) -> list:
    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            raw_sev = v.get("Severity", "UNKNOWN").upper()
            findings.append({
                "rule":         v.get("VulnerabilityID", "unknown"),
                "rule_full":    v.get("VulnerabilityID", "unknown"),
                "file":         result.get("Target", "unknown"),
                "line":         "N/A",
                "severity":     _normalize_sev(raw_sev),
                "description":  v.get("Description", "")[:300],
                "cwe":          "",
                "original_sev": raw_sev,
            })
    return findings


def _extract_dependency_check(data: dict) -> list:
    findings = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []):
            raw_sev = v.get("severity", "UNKNOWN").upper()
            findings.append({
                "rule":         v.get("name", "unknown"),
                "rule_full":    v.get("name", "unknown"),
                "file":         dep.get("fileName", "unknown"),
                "line":         "N/A",
                "severity":     _normalize_sev(raw_sev),
                "description":  v.get("description", "")[:300],
                "cwe":          "",
                "original_sev": raw_sev,
            })
    return findings


# ── Configuración por herramienta ─────────────────────────────────────────────

TOOL_CONFIG: dict = {

    "semgrep": {
        "display_name":     "Semgrep",
        "label":            "SAST",
        "system_context":   _build_context(["owasp_cheatsheet", "cwe"]),
        "extract":          _extract_semgrep,
        "max_per_sev":      {"ERROR": 10, "WARNING": 5, "INFO": 3},
        "sev_visual":       {"ERROR": _SEV_CRITICAL_HIGH, "WARNING": _SEV_MEDIUM, "INFO": _SEV_LOW_INFO},
        "issue_prefix":     "🚨 [SAST] Semgrep",
        "quality_gate_sev": "ERROR",
    },

    "gitleaks": {
        "display_name":     "Gitleaks",
        "label":            "Secrets",
        "system_context":   _build_context(["owasp_cheatsheet", "cwe"]),
        "extract":          _extract_gitleaks,
        "max_per_sev":      {"ERROR": 15, "WARNING": 10, "INFO": 5},
        "sev_visual":       {"ERROR": _SEV_CRITICAL},
        "issue_prefix":     "🔑 [Secrets] Gitleaks",
        "quality_gate_sev": "ERROR",
    },

    "kics": {
        "display_name":     "KICS",
        "label":            "IaC",
        "system_context":   _build_context(["owasp_cheatsheet", "cwe"]),
        "extract":          _extract_kics,
        "max_per_sev":      {"ERROR": 10, "WARNING": 5, "INFO": 2},
        "sev_visual":       {"ERROR": _SEV_CRITICAL_HIGH, "WARNING": _SEV_MEDIUM, "INFO": _SEV_LOW},
        "issue_prefix":     "🏗️ [IaC] KICS",
        "quality_gate_sev": "ERROR",
    },

    "trivy": {
        "display_name":     "Trivy",
        "label":            "Container",
        "system_context":   _build_context(["owasp_cheatsheet", "cwe"]),
        "extract":          _extract_trivy,
        "max_per_sev":      {"ERROR": 10, "WARNING": 5, "INFO": 2},
        "sev_visual":       {"ERROR": _SEV_CRITICAL_HIGH, "WARNING": _SEV_MEDIUM, "INFO": _SEV_LOW},
        "issue_prefix":     "🐳 [Container] Trivy",
        "quality_gate_sev": "ERROR",
    },

    "dependency-check": {
        "display_name":     "OWASP Dependency-Check",
        "label":            "SCA",
        "system_context":   _build_context(["owasp_cheatsheet", "cwe"]),
        "extract":          _extract_dependency_check,
        "max_per_sev":      {"ERROR": 10, "WARNING": 5, "INFO": 2},
        "sev_visual":       {"ERROR": _SEV_CRITICAL_HIGH, "WARNING": _SEV_MEDIUM, "INFO": _SEV_LOW},
        "issue_prefix":     "📦 [SCA] Dependency-Check",
        "quality_gate_sev": "ERROR",
    },
}
