#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════
# semgrep_authz.py — Autorización por middleware: declarar y verificar
#
# Usado por .github/workflows/sec-sast.yml.
#
# Problema: la regla de Semgrep `missing-or-broken-authorization` (C#/.NET)
# solo reconoce el atributo [Authorize] en la clase. En APIs secure-by-default
# (un middleware propio protege todo salvo [AllowAnonymous]) marca cada
# controller como falso positivo. Son `low`, y el consolidador bloquea con
# > 20 low acumulados: una API bien hecha puede bloquear su propio release.
#
# Solución (Opción D — declarar y verificar):
#   1. El repo consumidor DECLARA su middleware en .security/authz.yml
#      (versionado, revisado en PR). Esquema en DECLARATION_SCHEMA abajo.
#   2. Este script VERIFICA con una regla Semgrep generada que el middleware
#      está registrado (app.UseMiddleware<X>() / UseMiddleware(typeof(X)))
#      ANTES de MapControllers()/MapControllerRoute()/
#      MapDefaultControllerRoute()/UseEndpoints(), en el mismo bloque
#      (un registro dentro de un `if` NO verifica).
#   3. Solo si verifica, los hallazgos `missing-or-broken-authorization` del
#      mismo proyecto (.csproj) que el registro —o de los `scope` declarados—
#      se marcan como "cubiertos por middleware": siguen en el reporte pero
#      no suman al umbral del quality gate.
#   4. Inventario de [AllowAnonymous] / .AllowAnonymous(): en secure-by-default
#      esa lista es la superficie expuesta real. Se reporta para revisión.
#
# Fail-closed: declaración ausente, inválida, no verificada o cualquier error
# → ningún hallazgo se reclasifica (cuentan normal) + ::warning visible.
#
# Lo que esto NO valida (sigue siendo revisión manual, ver README):
#   - que el middleware aplique correctamente la autorización,
#   - exclusiones por path (UseWhen, listas de rutas públicas),
#   - registro vía métodos de extensión propios (app.UseAteneaIdentity()).
#
# Salida: JSON con el estado (ver build_result) consumido por los steps de
# reporte HTML y qg-summary de sec-sast.yml.
# ═══════════════════════════════════════════════════════════════════════════

import argparse
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

UPSTREAM_RULE_SUFFIX = "missing-or-broken-authorization"
RULE_REGISTERED = "authz-middleware-registered"
RULE_ANONYMOUS = "authz-allowanonymous-inventory"

# ─── Esquema de .security/authz.yml (v1) ─────────────────────────────────
#
#   version: 1                          # obligatorio, entero, solo 1
#   middleware:                         # obligatorio, lista no vacía
#     - name: AteneaIdentityMiddleware  # obligatorio: nombre de la clase C#
#                                       #   (identificador simple, sin namespace)
#       justification: >-               # obligatorio, >= 20 caracteres: por qué
#         Secure-by-default: ...        #   cubre la autorización y qué excepciones
#       scope:                          # opcional: rutas (relativas a la raíz)
#         - src/Atenea.Controllers      #   cuyos controllers cubre. Por defecto:
#                                       #   el proyecto (.csproj) del registro.
#
# Claves desconocidas = declaración inválida (evita typos silenciosos como
# `scopes:` o `justificacion:`).
DECLARATION_SCHEMA = {
    "top": {"version", "middleware"},
    "middleware": {"name", "justification", "scope"},
}
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
MIN_JUSTIFICATION = 20

MAP_METHODS = "MapControllers|MapControllerRoute|MapDefaultControllerRoute|UseEndpoints"


def gh(level, title, msg):
    print(f"::{level} title={title}::{msg}")


class DeclarationError(ValueError):
    pass


def load_declaration(path):
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise DeclarationError("el archivo debe ser un mapa YAML")
    unknown = set(data) - DECLARATION_SCHEMA["top"]
    if unknown:
        raise DeclarationError(f"claves desconocidas: {', '.join(sorted(unknown))}")
    if data.get("version") != 1:
        raise DeclarationError("`version` debe ser 1")
    mws = data.get("middleware")
    if not isinstance(mws, list) or not mws:
        raise DeclarationError("`middleware` debe ser una lista no vacía")

    out = []
    for i, mw in enumerate(mws):
        where = f"middleware[{i}]"
        if not isinstance(mw, dict):
            raise DeclarationError(f"{where} debe ser un mapa")
        unknown = set(mw) - DECLARATION_SCHEMA["middleware"]
        if unknown:
            raise DeclarationError(f"{where}: claves desconocidas: {', '.join(sorted(unknown))}")
        name = mw.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise DeclarationError(f"{where}.name debe ser un identificador C# simple (sin namespace)")
        just = mw.get("justification")
        if not isinstance(just, str) or len(just.strip()) < MIN_JUSTIFICATION:
            raise DeclarationError(f"{where}.justification es obligatoria (>= {MIN_JUSTIFICATION} caracteres)")
        scope = mw.get("scope")
        if scope is not None:
            if not isinstance(scope, list) or not scope or not all(isinstance(s, str) and s.strip() for s in scope):
                raise DeclarationError(f"{where}.scope debe ser una lista no vacía de rutas")
            scope = [_norm_scope(s, where) for s in scope]
        out.append({"name": name, "justification": just.strip(), "scope": scope})
    return out


def _norm_scope(s, where):
    p = posixpath.normpath(s.strip().replace("\\", "/"))
    if p.startswith("/") or p == ".." or p.startswith("../"):
        raise DeclarationError(f"{where}.scope: ruta fuera del repositorio: {s}")
    return "" if p == "." else p


def build_rules(names):
    # Los nombres ya pasaron NAME_RE, por lo que son seguros dentro del regex/YAML
    alternation = "|".join(sorted(set(names)))
    return {
        "rules": [
            {
                "id": RULE_REGISTERED,
                "languages": ["csharp"],
                "severity": "INFO",
                # El mensaje es SOLO el nombre del middleware: Semgrep OSS no
                # incluye metavars en la salida JSON, pero sí interpola el mensaje.
                "message": "$MW",
                "patterns": [
                    {"pattern-either": [
                        {"pattern": "$APP.UseMiddleware<$MW>();\n...\n$APP.$MAP(...);\n"},
                        {"pattern": "$APP.UseMiddleware(typeof($MW));\n...\n$APP.$MAP(...);\n"},
                    ]},
                    {"metavariable-regex": {"metavariable": "$MAP", "regex": f"^({MAP_METHODS})$"}},
                    {"metavariable-regex": {"metavariable": "$MW",
                                            "regex": rf"^(?:[A-Za-z_][A-Za-z0-9_]*\.)*({alternation})$"}},
                ],
            },
            {
                "id": RULE_ANONYMOUS,
                "languages": ["csharp"],
                "severity": "INFO",
                "message": "Acceso anónimo explícito: verificar que este endpoint debe ser público",
                "pattern-either": [
                    {"pattern": "[AllowAnonymous]\nclass $C { ... }\n"},
                    {"pattern": "[AllowAnonymous]\n$RET $M(...) { ... }\n"},
                    {"pattern": "$X.AllowAnonymous()"},
                ],
            },
        ]
    }


def run_semgrep(rules, target, excludes):
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as fh:
        yaml.safe_dump(rules, fh, sort_keys=False, allow_unicode=True)
        rules_path = fh.name
    try:
        cmd = [shutil.which("semgrep") or "semgrep", "scan", "--config", rules_path, "--json", "--metrics", "off", "--quiet"]
        for ex in excludes:
            cmd.append(f"--exclude={ex}")
        cmd.append(target)
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=False)
        data = json.loads(proc.stdout or "{}")
        if "results" not in data:
            raise RuntimeError(f"Semgrep no devolvió resultados (exit {proc.returncode}): {proc.stderr[-300:]}")
        return data["results"]
    finally:
        os.unlink(rules_path)


def _relpath(p, target):
    p = p.replace("\\", "/")
    t = posixpath.normpath(target.replace("\\", "/"))
    if t not in ("", ".") and p.startswith(t + "/"):
        p = p[len(t) + 1:]
    return posixpath.normpath(p)


def project_dir(rel_file, target):
    """Directorio del .csproj más cercano hacia arriba (sin salir del repo)."""
    d = posixpath.dirname(rel_file)
    while True:
        abs_d = os.path.join(target, d) if d else target
        try:
            if any(f.endswith(".csproj") for f in os.listdir(abs_d)):
                return d
        except OSError:
            pass
        if not d:
            # Sin .csproj: fail-closed al directorio del propio archivo
            return posixpath.dirname(rel_file)
        d = posixpath.dirname(d)


def in_scope(path, scope):
    return scope == "" or path == scope or path.startswith(scope + "/")


def build_result(status, message, declared=None, registrations=None, scopes=None,
                 covered=None, anonymous=None):
    return {
        "schema_version": "1.0",
        "status": status,            # not_declared | invalid | verified | partial | not_verified | error
        "message": message,
        "middleware": declared or [],
        "registrations": registrations or [],
        "covered_scopes": scopes or [],
        "covered_findings": covered or [],   # [{check_id, path, line}]
        "allow_anonymous": anonymous or [],  # [{path, line}]
    }


def evaluate(decl_path, raw_path, target, excludes):
    if not os.path.isfile(decl_path):
        return build_result("not_declared", "Sin declaración de autorización por middleware")

    try:
        declared = load_declaration(decl_path)
    except (DeclarationError, yaml.YAMLError) as exc:
        msg = f"{decl_path} inválido: {exc}. Los hallazgos de autorización cuentan normal."
        gh("warning", "Autorización por middleware NO aplicada", msg)
        return build_result("invalid", msg)

    results = run_semgrep(build_rules([m["name"] for m in declared]), target, excludes)

    registrations, anonymous = [], []
    for r in results:
        rid = r.get("check_id", "").rsplit(".", 1)[-1]
        rel = _relpath(r.get("path", ""), target)
        line = r.get("start", {}).get("line")
        if rid == RULE_REGISTERED:
            mw_text = r.get("extra", {}).get("message", "")
            name = mw_text.rsplit(".", 1)[-1].strip()
            registrations.append({"middleware": name, "path": rel, "line": line,
                                  "project_dir": project_dir(rel, target)})
        elif rid == RULE_ANONYMOUS:
            anonymous.append({"path": rel, "line": line})

    scopes, missing = [], []
    for mw in declared:
        regs = [g for g in registrations if g["middleware"] == mw["name"]]
        if not regs:
            missing.append(mw["name"])
            continue
        scopes.extend(mw["scope"] if mw["scope"] is not None else [g["project_dir"] for g in regs])
    scopes = sorted(set(scopes))

    if not scopes:
        msg = (f"Middleware declarado ({', '.join(missing)}) pero NO verificado: no se encontró "
               f"UseMiddleware<X>() / UseMiddleware(typeof(X)) antes de MapControllers()/UseEndpoints() "
               f"en el mismo bloque. Los hallazgos de autorización cuentan normal.")
        gh("warning", "Autorización por middleware NO verificada", msg)
        return build_result("not_verified", msg, declared, registrations, [], [], anonymous)

    covered = []
    try:
        with open(raw_path, encoding="utf-8") as fh:
            raw = json.load(fh).get("results", [])
    except (OSError, ValueError):
        raw = []
    for r in raw:
        if not r.get("check_id", "").endswith(UPSTREAM_RULE_SUFFIX):
            continue
        rel = _relpath(r.get("path", ""), target)
        if any(in_scope(rel, s) for s in scopes):
            covered.append({"check_id": r.get("check_id"), "path": r.get("path"),
                            "line": r.get("start", {}).get("line")})

    status = "verified"
    msg = (f"Middleware verificado ({', '.join(sorted({g['middleware'] for g in registrations}))}); "
           f"{len(covered)} hallazgo(s) de autorización cubiertos en: {', '.join(s or '.' for s in scopes)}")
    if missing:
        status = "partial"
        gh("warning", "Autorización por middleware parcialmente verificada",
           f"Declarado pero NO verificado: {', '.join(missing)}. Sus controllers cuentan normal.")
    gh("notice", "Autorización por middleware", msg)
    return build_result(status, msg, declared, registrations, scopes, covered, anonymous)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--declaration", default=".security/authz.yml")
    ap.add_argument("--semgrep-raw", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--target", default=".")
    ap.add_argument("--exclude", action="append", default=[])
    args = ap.parse_args()

    try:
        result = evaluate(args.declaration, args.semgrep_raw, args.target, args.exclude)
    except Exception as exc:  # noqa: BLE001 — fail-closed, nunca romper el scan
        msg = f"Error verificando autorización por middleware ({exc}). Los hallazgos cuentan normal."
        gh("warning", "Autorización por middleware NO aplicada", msg)
        result = build_result("error", msg)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
