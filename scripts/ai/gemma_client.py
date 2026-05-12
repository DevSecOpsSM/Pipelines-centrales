#!/usr/bin/env python3
"""
SSDLC AI Remediation Engine — pipelines-centrales
Llama a Google AI Studio (Gemma) por cada hallazgo y crea GitHub Issues.

Uso:
  python gemma_client.py --tool semgrep  --results reports/semgrep-raw.json
  python gemma_client.py --tool gitleaks --results gitleaks-results.json
  python gemma_client.py --tool trivy    --results trivy-results.json

Variables de entorno requeridas:
  GEMMA_API_KEY   API key de Google AI Studio
  GH_TOKEN        Token de GitHub (inyectado automáticamente por Actions)

Variables opcionales:
  GEMINI_MODEL    Modelo a usar (default: gemma-4-26b-a4b-it)
  GITHUB_REPOSITORY  Nombre del repo caller (inyectado por Actions)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(__file__))
from prompt_templates import TOOL_CONFIG


# ── Cliente de Google AI Studio ───────────────────────────────────────────────

class GemmaClient:

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model   = model

    def _build_payload(self, system_context: str, user_prompt: str) -> dict:
        return {
            "contents": [
                {"role": "user",  "parts": [{"text": system_context}]},
                {"role": "model", "parts": [{"text": "Understood. I will output only the corrected "
                                                      "code block and one citation sentence."}]},
                {"role": "user",  "parts": [{"text": user_prompt}]},
            ],
            "generationConfig": {
                "temperature":     0.1,
                "maxOutputTokens": 1024,
            },
        }

    def _call_api(self, url: str, headers: dict, payload: dict) -> tuple:
        """Single API attempt. Returns (result, error_msg, retry_wait_seconds).
        retry_wait=0 means no retry; >0 means wait that many seconds then retry."""
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=45)
            resp.raise_for_status()
            raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            return self._clean(raw), None, 0
        except requests.exceptions.Timeout:
            return None, "> ⚠️ *Timeout tras 45s. Requiere revisión manual.*", 0
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response else 0
            if code == 0:
                raw_msg = str(e)
                if "429" in raw_msg:
                    code = 429
                elif "500" in raw_msg:
                    code = 500
            if code == 429:
                return None, None, 65   # rate limit: esperar 65s (bucket renueva en 60s)
            if code in (500, 503):
                return None, None, 8    # server error: backoff exponencial
            body = e.response.text[:300] if e.response else str(e)
            return None, f"> ⚠️ *Error HTTP {code}: `{body}`*", 0
        except Exception as e:
            return None, f"> ⚠️ *Error inesperado: {str(e)}*", 0

    def ask(self, system_context: str, user_prompt: str) -> str:
        url     = f"{self.BASE_URL}/{self.model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload = self._build_payload(system_context, user_prompt)

        for attempt in range(3):
            result, error, retry_wait = self._call_api(url, headers, payload)
            if result is not None:
                return result
            if retry_wait == 0:
                return error
            # 429 → siempre 65s; 500 → exponencial (8s, 16s, 24s)
            wait = retry_wait if retry_wait >= 60 else retry_wait * (attempt + 1)
            print(f"   ⏳ Esperando {wait}s antes de reintentar (intento {attempt + 1}/3)...")
            time.sleep(wait)

        return "> ⚠️ *Sin respuesta tras 3 intentos. Requiere revisión manual.*"

    @staticmethod
    def _clean(raw: str) -> str:
        """
        Descarta el razonamiento interno de Gemma.
        Extrae únicamente el último bloque de código y la última línea de Remediación.
        """
        code_blocks  = re.findall(r"```[\s\S]*?```", raw)
        remediacines = re.findall(r"(?:\*\*)?[Rr]emediaci[oó]n:?(?:\*\*)?\s*(.+)", raw)

        parts = []
        if code_blocks:
            parts.append(code_blocks[-1])
        if remediacines:
            parts.append(f"**Remediación:** {remediacines[-1].strip()}")

        return "\n\n".join(parts) if parts else raw


# ── Gestión de Issues en GitHub ───────────────────────────────────────────────

class IssueManager:

    def __init__(self):
        self._existing: set = set()
        self._load_existing()

    def _load_existing(self):
        try:
            out = subprocess.check_output(
                ["gh", "issue", "list", "--state", "open", "--json", "title"],
                stderr=subprocess.DEVNULL,
            )
            for issue in json.loads(out.decode("utf-8")):
                self._existing.add(issue["title"])
        except Exception:
            pass

    def exists(self, title: str) -> bool:
        return title in self._existing

    def create(self, title: str, body: str) -> bool:
        try:
            subprocess.run(
                ["gh", "issue", "create", "--title", title, "--body", body],
                check=True,
                stderr=subprocess.DEVNULL,
            )
            self._existing.add(title)
            return True
        except Exception:
            return False


# ── Construcción del cuerpo del Issue ─────────────────────────────────────────

def _build_issue_body(finding: dict, config: dict, remediacion: str) -> str:
    sev_label = config["sev_visual"].get(finding["severity"], finding["severity"])
    cwe_line  = (f"\n**CWE**: `{finding['cwe']}`" if finding.get("cwe") else "")

    return (
        f"### 🛡️ Hallazgo de Seguridad Automatizado\n\n"
        f"**Herramienta**: {config['display_name']}\n"
        f"**Severidad**: {sev_label}\n"
        f"**Archivo**: `{finding['file']}` (Línea: {finding['line']})\n"
        f"**Regla**: `{finding['rule']}`{cwe_line}\n\n"
        f"**Descripción**:\n> {finding['description']}\n\n"
        f"### 🤖 Propuesta de Remediación (Gemma AI — OWASP)\n"
        f"{remediacion}\n\n"
        f"---\n"
        f"*Remediación generada por IA. Verifique antes de implementar.*"
    )


# ── Procesamiento de un hallazgo individual ───────────────────────────────────

def _process_finding(
    finding: dict, config: dict, ai: "GemmaClient | None", issues: IssueManager
) -> bool:
    """Consult AI and create a GitHub Issue for one finding. Returns True if created."""
    title = f"{config['issue_prefix']}: {finding['rule']} en {finding['file']}"
    if issues.exists(title):
        print(f"[AI] Issue ya existe, omitiendo: {finding['rule']}")
        return False

    if ai:
        print(f"🧠 [{config['label']}] Consultando Gemma → {finding['rule']}...")
        cwe_line = f"\nCWE: {finding['cwe']}" if finding.get("cwe") else ""
        user_prompt = (
            f"Fix this vulnerability. Return ONLY the corrected code block "
            f"+ one citation sentence.\n\n"
            f"Rule: {finding['rule_full']}\n"
            f"File: {finding['file']} (Line {finding['line']})\n"
            f"Description: {finding['description']}{cwe_line}"
        )
        remediacion = ai.ask(config["system_context"], user_prompt)
    else:
        remediacion = "> ⚠️ *Asistencia IA desactivada: falta GEMMA_API_KEY.*"

    body = _build_issue_body(finding, config, remediacion)
    if issues.create(title, body):
        print(f"   ✅ Issue creado: {title}")
        return True

    print(f"   ❌ Error creando issue: {title}")
    return False


# ── Orquestador principal ─────────────────────────────────────────────────────

def run(tool: str, results_path: str) -> None:

    if tool not in TOOL_CONFIG:
        print(f"[AI] Herramienta desconocida: '{tool}'. "
              f"Disponibles: {list(TOOL_CONFIG.keys())}")
        sys.exit(0)

    config = TOOL_CONFIG[tool]

    # Cargar resultados
    if not os.path.exists(results_path):
        print(f"[AI] Archivo no encontrado: {results_path}")
        sys.exit(0)

    try:
        with open(results_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"[AI] Error leyendo JSON: {e}")
        sys.exit(0)

    findings = config["extract"](data)
    if not findings:
        print(f"[AI] Sin hallazgos en {results_path}. Nada que procesar.")
        sys.exit(0)

    # Inicializar cliente IA y gestor de issues
    api_key = os.environ.get("GEMMA_API_KEY", "")
    model   = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    ai      = GemmaClient(api_key, model) if api_key else None
    issues  = IssueManager()

    if not ai:
        print("[AI] GEMMA_API_KEY no configurada. Se crean issues sin remediación IA.")

    max_per_sev = config["max_per_sev"]
    counts      = dict.fromkeys(max_per_sev, 0)
    totals      = dict.fromkeys(max_per_sev, 0)
    created     = 0

    for finding in findings:
        sev = finding["severity"]
        totals[sev] = totals.get(sev, 0) + 1

        if counts.get(sev, 0) >= max_per_sev.get(sev, 0):
            continue

        if _process_finding(finding, config, ai, issues):
            counts[sev] = counts.get(sev, 0) + 1
            created += 1
        if ai:
            time.sleep(5)  # ~12 RPM — margen bajo el límite de 15 RPM del free tier

    # Resumen
    print(f"\n[AI] Proceso completado — Issues nuevos: {created}")
    for sev, total in totals.items():
        print(f"     {sev}: {total} hallazgo(s) totales, {counts.get(sev, 0)} issues creados")

    # Quality Gate
    qg_sev = config.get("quality_gate_sev", "ERROR")
    if totals.get(qg_sev, 0) > 0:
        print(f"\n❌ QUALITY GATE: {totals[qg_sev]} hallazgo(s) de severidad {qg_sev}.")
        print("🛑 El pipeline falla para bloquear el pase a producción.")
        sys.exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SSDLC AI Remediation Engine — pipelines-centrales"
    )
    parser.add_argument(
        "--tool",
        required=True,
        choices=list(TOOL_CONFIG.keys()),
        help="Herramienta fuente: semgrep, gitleaks, trivy, dependency-check",
    )
    parser.add_argument(
        "--results",
        required=True,
        help="Ruta al archivo JSON de resultados de la herramienta",
    )
    args = parser.parse_args()
    run(args.tool, args.results)
