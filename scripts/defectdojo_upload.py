#!/usr/bin/env python3
"""
DefectDojo Upload — sube los raw JSONs de todos los scanners SSDLC al servidor
DefectDojo on-prem usando el endpoint /api/v2/reimport-scan/ con los parsers
nativos por herramienta.

Uso:
    python3 defectdojo_upload.py \
        --raw-dir raw-jsons/ \
        --repo owner/name \
        --branch main \
        --sha abc123 \
        --run-id 123456 \
        --dd-url https://defectdojo.internal \
        --dd-token $DD_TOKEN \
        --summary-out reports/dd-summary.json

Comportamiento:
    - Product   = nombre del repo (part despues del `/`)
    - Engagement = nombre de la rama
    - Test      = "{Tool} - {branch}" — un test por scanner por rama
    - auto_create_context=true → DD crea Product/Engagement/Test si no existen
    - close_old_findings=true  → los hallazgos que ya no aparecen se marcan
                                  como Mitigated dentro del engagement
    - SonarQube NO se sube desde aqui: se integra nativamente en DD via su
      configuracion API key (evita duplicados).

Modo Auditoria: NUNCA falla el pipeline. Solo reporta status por herramienta.
"""
import argparse
import json
import sys
from datetime import date
from pathlib import Path

import requests


TOOL_MAP = [
    # (nombre archivo raw, scan_type DefectDojo, test_title corto)
    ("semgrep-raw.json",             "Semgrep JSON Report",       "Semgrep"),
    ("gitleaks-raw.json",            "Gitleaks Scan",             "Gitleaks"),
    ("dependency-check-report.json", "Dependency Check Scan",     "Dependency-Check"),
    ("checkov-raw.json",             "Checkov Scan",              "Checkov"),
    ("kics-results.json",            "KICS Scan",                 "KICS"),
    ("trivy-raw.json",               "Trivy Scan",                "Trivy"),
    ("hadolint-raw.json",            "Hadolint Dockerfile check", "Hadolint"),
]


def _base_payload(scan_type, test_title, product_name, engagement_name,
                  sha, branch, run_id, repo_full):
    """Payload comun para import-scan y reimport-scan."""
    return {
        "scan_type":                        scan_type,
        "product_name":                     product_name,
        "engagement_name":                  engagement_name,
        "test_title":                       f"{test_title} - {branch}",
        "auto_create_context":              "true",
        "scan_date":                        date.today().isoformat(),
        "active":                           "true",
        "verified":                         "false",
        "minimum_severity":                 "Info",
        "push_to_jira":                     "false",
        "commit_hash":                      sha,
        "branch_tag":                       branch,
        "build_id":                         str(run_id),
        "service":                          product_name,
        "source_code_management_uri":       f"https://github.com/{repo_full}",
        "tags":                             f"branch:{branch},sha:{sha[:7]},tool:{test_title.lower()}",
    }


def _reimport(dd_url, dd_token, raw_path, payload):
    endpoint = f"{dd_url.rstrip('/')}/api/v2/reimport-scan/"
    headers  = {"Authorization": f"Token {dd_token}"}
    payload  = {
        **payload,
        "close_old_findings":               "true",
        "close_old_findings_product_scope": "false",
    }
    with open(raw_path, "rb") as fh:
        files = {"file": (Path(raw_path).name, fh, "application/json")}
        return requests.post(endpoint, headers=headers, files=files,
                             data=payload, timeout=180)


def _import(dd_url, dd_token, raw_path, payload):
    endpoint = f"{dd_url.rstrip('/')}/api/v2/import-scan/"
    headers  = {"Authorization": f"Token {dd_token}"}
    with open(raw_path, "rb") as fh:
        files = {"file": (Path(raw_path).name, fh, "application/json")}
        return requests.post(endpoint, headers=headers, files=files,
                             data=payload, timeout=180)


def upload_tool(dd_url, dd_token, raw_path, scan_type, test_title,
                product_name, engagement_name, sha, branch, run_id, repo_full):
    """
    Intenta reimport-scan primero (dedup + close_old_findings).
    Si el test no existe todavia, cae a import-scan (primera corrida).
    """
    payload = _base_payload(scan_type, test_title, product_name, engagement_name,
                            sha, branch, run_id, repo_full)

    try:
        r = _reimport(dd_url, dd_token, raw_path, payload)
    except requests.RequestException as e:
        return False, f"error de red (reimport): {e}"

    if r.status_code in (200, 201):
        try:
            body    = r.json()
            test_id = body.get("test") or body.get("test_id") or "?"
            return True, f"reimport OK (test_id={test_id})"
        except ValueError:
            return True, "reimport OK"

    # Fallback: el test aun no existe en el engagement → import-scan
    txt = r.text.lower()
    if r.status_code in (400, 404) and ("not found" in txt or "does not exist" in txt or "no test" in txt):
        try:
            r2 = _import(dd_url, dd_token, raw_path, payload)
        except requests.RequestException as e:
            return False, f"error de red (import): {e}"
        if r2.status_code in (200, 201):
            return True, "import OK (primera corrida)"
        return False, f"HTTP {r2.status_code} import: {r2.text[:200]}"

    return False, f"HTTP {r.status_code}: {r.text[:200]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir",     required=True, help="Directorio con los raw JSONs")
    ap.add_argument("--repo",        required=True, help="owner/name (github.repository)")
    ap.add_argument("--branch",      required=True, help="Rama / engagement")
    ap.add_argument("--sha",         required=True, help="Commit SHA completo")
    ap.add_argument("--run-id",      required=True, help="github.run_id")
    ap.add_argument("--dd-url",      required=True, help="URL base del servidor DefectDojo")
    ap.add_argument("--dd-token",    required=True, help="Token API de DefectDojo")
    ap.add_argument("--summary-out", help="Ruta para escribir resumen JSON (opcional)")
    args = ap.parse_args()

    repo_full       = args.repo
    repo_name       = repo_full.split("/")[-1]
    product_name    = repo_name
    engagement_name = args.branch

    print("=" * 63)
    print("DefectDojo Upload")
    print("=" * 63)
    print(f"Product:    {product_name}")
    print(f"Engagement: {engagement_name}")
    print(f"Commit:     {args.sha[:7]}")
    print(f"DD URL:     {args.dd_url}")
    print(f"Raw dir:    {args.raw_dir}")
    print()

    raw_dir = Path(args.raw_dir)
    results = []

    for raw_name, scan_type, test_title in TOOL_MAP:
        # Busca el archivo tambien en subcarpetas (por si download-artifact anida)
        candidates = list(raw_dir.rglob(raw_name))
        if not candidates:
            print(f"  - {test_title:20s} SKIP (no encontrado: {raw_name})")
            results.append({"tool": test_title, "status": "skipped", "reason": "file not found"})
            continue

        raw_path = candidates[0]
        if raw_path.stat().st_size == 0:
            print(f"  - {test_title:20s} SKIP (archivo vacio)")
            results.append({"tool": test_title, "status": "skipped", "reason": "empty file"})
            continue

        ok, msg = upload_tool(
            args.dd_url, args.dd_token, str(raw_path),
            scan_type, test_title,
            product_name, engagement_name,
            args.sha, args.branch, args.run_id, repo_full,
        )
        status = "uploaded" if ok else "failed"
        icon   = "+" if ok else "x"
        print(f"  {icon} {test_title:20s} {msg}")
        results.append({
            "tool":    test_title,
            "status":  status,
            "message": msg,
            "file":    raw_name,
        })

    uploaded = sum(1 for r in results if r["status"] == "uploaded")
    failed   = sum(1 for r in results if r["status"] == "failed")
    skipped  = sum(1 for r in results if r["status"] == "skipped")
    print()
    print("=" * 63)
    print(f"Resumen: {uploaded} subido(s) - {failed} fallo(s) - {skipped} omitido(s)")
    print("=" * 63)

    if args.summary_out:
        summary = {
            "product":    product_name,
            "engagement": engagement_name,
            "commit":     args.sha,
            "branch":     args.branch,
            "dd_url":     args.dd_url,
            "uploaded":   uploaded,
            "failed":     failed,
            "skipped":    skipped,
            "details":    results,
        }
        Path(args.summary_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary_out).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Resumen escrito en {args.summary_out}")

    # Modo Auditoria: nunca fallar el pipeline
    return 0


if __name__ == "__main__":
    sys.exit(main())
