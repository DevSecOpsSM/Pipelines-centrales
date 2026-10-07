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
#   2. Este script VERIFICA con reglas Semgrep generadas que el middleware
#      está registrado ANTES de MapControllers()/MapControllerRoute()/
#      MapDefaultControllerRoute()/UseEndpoints(), en el mismo bloque
#      (un registro dentro de un `if` NO verifica). Dos formas aceptadas:
#        a) directa:  app.UseMiddleware<X>() / app.UseMiddleware(typeof(X))
#        b) método de extensión definido en el MISMO proyecto (.csproj):
#             public static IApplicationBuilder AddIdentityMiddleware(this IApplicationBuilder app)
#             { app.UseMiddleware<X>(); return app; }
#           cuyo cuerpo llama a UseMiddleware<X>() como sentencia directa
#           (no dentro de if/else/switch/bucles/lambdas). Esto se comprueba
#           en Python sobre el código fuente (verify_extension) porque Semgrep
#           no puede expresar "sentencia directa" en C#. Además,
#           app.AddIdentityMiddleware() debe llamarse antes del mapeo.
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
#   - exclusiones por path (UseWhen, listas de rutas públicas como un
#     AnonymousPaths dentro del propio middleware),
#   - extensiones definidas en OTRO proyecto (p. ej. una librería compartida):
#     no verifican (fail-closed).
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
RULE_EXT_DEF = "authz-extension-definition"
RULE_EXT_CALL = "authz-extension-call"
BUILDER_TYPES = "IApplicationBuilder|WebApplication"

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
                # Candidatos: cualquier UseMiddleware<X> sobre el parámetro
                # `this` de un método de extensión. La comprobación estricta
                # (sentencia directa del cuerpo) la hace verify_extension().
                "id": RULE_EXT_DEF,
                "languages": ["csharp"],
                "severity": "INFO",
                "message": "$EXT|$A",
                "patterns": [
                    {"pattern-either": [
                        {"pattern-inside": "public static $RT $EXT(this $BT $A, ...) { ... }\n"},
                        {"pattern-inside": "public static $RT $EXT(this $BT $A, ...) => $BODY;\n"},
                    ]},
                    {"pattern-either": [
                        {"pattern": "$A.UseMiddleware<$MW>(...)"},
                        {"pattern": "$A.UseMiddleware(typeof($MW), ...)"},
                    ]},
                    {"metavariable-regex": {"metavariable": "$BT", "regex": f"^({BUILDER_TYPES})$"}},
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


def build_call_rule(ext_names):
    # Los nombres ya pasaron NAME_RE
    alternation = "|".join(sorted(set(ext_names)))
    return {
        "rules": [{
            "id": RULE_EXT_CALL,
            "languages": ["csharp"],
            "severity": "INFO",
            "message": "$EXT",
            "patterns": [
                {"pattern": "$APP.$EXT(...);\n...\n$APP.$MAP(...);\n"},
                {"metavariable-regex": {"metavariable": "$MAP", "regex": f"^({MAP_METHODS})$"}},
                {"metavariable-regex": {"metavariable": "$EXT", "regex": f"^({alternation})$"}},
            ],
        }]
    }


# ─── Verificación estructural del cuerpo de un método de extensión ───────

_MASK_RE = re.compile(
    r'//[^\n]*'                    # comentario de línea
    r'|/\*.*?\*/'                  # comentario de bloque
    r'|@"(?:[^"]|"")*"'            # cadena verbatim
    r'|\$?"(?:\\.|[^"\\\n])*"'     # cadena normal / interpolada
    r"|'(?:\\.|[^'\\\n])'",        # carácter
    re.S,
)


def _mask(text):
    """Reemplaza comentarios y literales por espacios (misma longitud), para
    que un UseMiddleware comentado o dentro de una cadena no cuente."""
    return _MASK_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _stmt_re(param, names):
    mw = rf"(?:[A-Za-z_]\w*\.)*(?:{'|'.join(sorted(set(names)))})"
    call = (rf"{re.escape(param)}\s*\.\s*UseMiddleware\s*"
            rf"(?:<\s*{mw}\s*>\s*\(.*\)|\(\s*typeof\s*\(\s*{mw}\s*\).*\))")
    chain = r"(?:\s*\.\s*[A-Za-z_]\w*\s*(?:<[^;]*?>)?\s*\(.*\))*"
    return re.compile(rf"^(?:return\s+)?{call}{chain}$", re.S)


def verify_extension(path, ext, param, names, byte_off):
    """Devuelve el middleware registrado si el método de extensión `ext` llama
    a `param`.UseMiddleware<X>() como sentencia DIRECTA de su cuerpo (nivel 1
    de llaves, fuera de paréntesis, sin if/else/case delante) o como
    cuerpo-expresión. Si no, None (fail-closed)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    text = _mask(raw.decode("utf-8", errors="replace"))
    # Semgrep reporta offsets en bytes; el archivo puede tener tildes
    off = len(raw[:byte_off].decode("utf-8", errors="replace"))

    decl_re = re.compile(rf"\b{re.escape(ext)}\s*\(\s*this\s+(?:{BUILDER_TYPES})\s+{re.escape(param)}\b")
    decls = [m for m in decl_re.finditer(text) if m.start() < off]
    if not decls:
        return None

    # Saltar la lista de parámetros
    i, depth = text.index("(", decls[-1].start()), 0
    while i < len(text):
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        i += 1
        if depth == 0:
            break
    while i < len(text) and text[i].isspace():
        i += 1

    statements = []
    if text.startswith("=>", i):                       # cuerpo-expresión
        end = text.find(";", i)
        if end != -1:
            statements.append((i + 2, end))
    elif i < len(text) and text[i] == "{":             # cuerpo con llaves
        brace, paren, seg = 1, 0, i + 1
        i += 1
        while i < len(text) and brace > 0:
            c = text[i]
            if c == "(":
                paren += 1
            elif c == ")":
                paren -= 1
            elif c == "{" and paren == 0:
                brace += 1
            elif c == "}" and paren == 0:
                brace -= 1
                if brace == 1:
                    seg = i + 1        # lo que había antes del bloque anidado se descarta
            elif c == ";" and brace == 1 and paren == 0:
                statements.append((seg, i))
                seg = i + 1
            i += 1

    for a, b in statements:
        stmt = text[a:b].strip()
        if a <= off < b and _stmt_re(param, names).match(stmt):
            for n in sorted(set(names), key=len, reverse=True):
                if re.search(rf"\b{re.escape(n)}\b", stmt):
                    return n
    return None


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

    names = [m["name"] for m in declared]
    registrations, anonymous, ext_defs = [], [], []
    for r in results:
        rid = r.get("check_id", "").rsplit(".", 1)[-1]
        rel = _relpath(r.get("path", ""), target)
        line = r.get("start", {}).get("line")
        if rid == RULE_REGISTERED:
            mw_text = r.get("extra", {}).get("message", "")
            name = mw_text.rsplit(".", 1)[-1].strip()
            registrations.append({"middleware": name, "path": rel, "line": line,
                                  "via": "UseMiddleware", "project_dir": project_dir(rel, target)})
        elif rid == RULE_ANONYMOUS:
            anonymous.append({"path": rel, "line": line})
        elif rid == RULE_EXT_DEF:
            ext, _, param = r.get("extra", {}).get("message", "").partition("|")
            ext, param = ext.strip(), param.strip()
            if not (NAME_RE.match(ext) and NAME_RE.match(param)):
                continue
            mw = verify_extension(os.path.join(target, rel), ext, param, names,
                                  r.get("start", {}).get("offset", -1))
            if mw:
                ext_defs.append({"ext": ext, "middleware": mw, "path": rel, "line": line,
                                 "project_dir": project_dir(rel, target)})

    # Llamadas a extensiones verificadas antes del mapeo de controllers. Solo
    # cuentan si la extensión está definida en el MISMO proyecto que la llamada
    # (una extensión homónima en otro proyecto no puede validar por error).
    if ext_defs:
        for r in run_semgrep(build_call_rule([d["ext"] for d in ext_defs]), target, excludes):
            ext = r.get("extra", {}).get("message", "").strip()
            rel = _relpath(r.get("path", ""), target)
            pdir = project_dir(rel, target)
            for d in ext_defs:
                if d["ext"] == ext and d["project_dir"] == pdir:
                    registrations.append({"middleware": d["middleware"], "path": rel,
                                          "line": r.get("start", {}).get("line"),
                                          "via": f"{ext}() → {d['path']}:{d['line']}",
                                          "project_dir": pdir})
                    break

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
               f"UseMiddleware<X>() / UseMiddleware(typeof(X)) —directo o vía un método de extensión "
               f"del mismo proyecto— antes de MapControllers()/UseEndpoints() en el mismo bloque. "
               f"Los hallazgos de autorización cuentan normal.")
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
