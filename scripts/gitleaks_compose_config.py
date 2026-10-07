#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════
# gitleaks_compose_config.py — Compone la config efectiva de Gitleaks
#
# Usado por .github/workflows/sec-secrets.yml.
#
# Por qué existe: el [extend] nativo de Gitleaks hereda las REGLAS del config
# padre pero descarta sus [[allowlists]] globales (verificado en v8.30.1). Si
# el consumidor extendiera el config central, perdería en silencio FP-01/FP-02;
# si el central extendiera al consumidor, se perderían las del consumidor.
#
# Política: el consumidor solo puede AÑADIR, nunca QUITAR cobertura.
#   Config efectiva = reglas por defecto de Gitleaks
#                   + reglas y allowlists del .gitleaks.toml del consumidor
#                   + allowlists centrales (config/gitleaks.toml), siempre.
#   Campos del consumidor que reducirían cobertura se ignoran con ::warning:
#     - extend.useDefault distinto de true  → se fuerza a true
#     - extend.disabledRules                → se descarta
#     - extend.path                         → se descarta (la cadena la controla CI)
#   El formato legacy [allowlist] (singular) se convierte a [[allowlists]]
#   (Gitleaks >= 8.25 no permite mezclar ambos).
#
# Nunca hace fallar el job: ante cualquier error inesperado escribe la config
# central sin cambios (más hallazgos, nunca menos).
#
# Uso:
#   python3 gitleaks_compose_config.py --central config/gitleaks.toml \
#       --consumer .gitleaks.toml --output gitleaks-effective.toml
# ═══════════════════════════════════════════════════════════════════════════

import argparse
import json
import os
import shutil
import sys
import tomllib

BARE_KEY_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def gh(level, title, msg):
    """Anotación de GitHub Actions (::notice / ::warning)."""
    print(f"::{level} title={title}::{msg}")


# ─── Serializador TOML mínimo (tomllib solo lee) ─────────────────────────
# Cubre los tipos que usa un config de Gitleaks: str, int, float, bool,
# listas de escalares, tablas y arrays de tablas. Las cadenas se emiten como
# basic strings vía json.dumps (sus escapes son un subconjunto válido TOML).

def _key(k):
    return k if k and set(k) <= BARE_KEY_CHARS else json.dumps(k, ensure_ascii=False)


def _scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(_scalar(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{_key(k)} = {_scalar(x)}" for k, x in v.items()) + "}"
    raise TypeError(f"Tipo TOML no soportado: {type(v).__name__}")


def _is_table_array(v):
    return isinstance(v, list) and v and all(isinstance(x, dict) for x in v)


def _emit(table, path, out):
    simple = {k: v for k, v in table.items() if not isinstance(v, dict) and not _is_table_array(v)}
    for k, v in simple.items():
        out.append(f"{_key(k)} = {_scalar(v)}")
    for k, v in table.items():
        sub = path + [_key(k)]
        if isinstance(v, dict):
            out.append("")
            out.append(f"[{'.'.join(sub)}]")
            _emit(v, sub, out)
        elif _is_table_array(v):
            for item in v:
                out.append("")
                out.append(f"[[{'.'.join(sub)}]]")
                _emit(item, sub, out)


def dumps(data):
    out = []
    _emit(data, [], out)
    return "\n".join(out).lstrip("\n") + "\n"


# ─── Composición ─────────────────────────────────────────────────────────

def compose(central, consumer):
    effective = dict(consumer)

    extend = dict(consumer.get("extend") or {})
    if extend.get("useDefault") is not True:
        gh("warning", "Gitleaks config",
           "El .gitleaks.toml del consumidor no hereda las reglas por defecto "
           "(extend.useDefault != true). Se fuerza useDefault = true: el consumidor solo puede añadir cobertura.")
    if extend.get("disabledRules"):
        gh("warning", "Gitleaks config",
           f"extend.disabledRules del consumidor ignorado ({', '.join(map(str, extend['disabledRules']))}). "
           "Desactivar reglas reduce cobertura y debe tramitarse en pipelines-centrales vía PR.")
    if extend.get("path"):
        gh("warning", "Gitleaks config",
           "extend.path del consumidor ignorado: la cadena de configuración la controla el pipeline central.")
    effective["extend"] = {"useDefault": True}

    allowlists = list(consumer.get("allowlists") or [])
    legacy = effective.pop("allowlist", None)
    if legacy:
        gh("notice", "Gitleaks config",
           "Formato legacy [allowlist] del consumidor convertido a [[allowlists]]. Se recomienda migrarlo en el repo.")
        allowlists.insert(0, legacy)

    central_allowlists = list(central.get("allowlists") or [])
    effective["allowlists"] = allowlists + central_allowlists
    return effective, len(allowlists), len(central_allowlists)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--central", required=True)
    ap.add_argument("--consumer", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    if not os.path.isfile(args.consumer):
        shutil.copyfile(args.central, args.output)
        gh("notice", "Gitleaks config", "Usando config central (pipelines-centrales/config/gitleaks.toml)")
        return 0

    try:
        with open(args.central, "rb") as fh:
            central = tomllib.load(fh)
        try:
            with open(args.consumer, "rb") as fh:
                consumer = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            gh("warning", "Gitleaks config",
               f".gitleaks.toml del consumidor no es TOML válido ({exc}). Se ignora y se usa la config central.")
            shutil.copyfile(args.central, args.output)
            return 0

        effective, n_consumer, n_central = compose(central, consumer)
        text = ("# Generado por pipelines-centrales/scripts/gitleaks_compose_config.py — no editar\n"
                + dumps(effective))

        # Round-trip: lo que se escribe debe parsear exactamente a lo compuesto
        if tomllib.loads(text) != effective:
            raise ValueError("round-trip TOML no coincide")

        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        gh("notice", "Gitleaks config",
           f"Config compuesta: defaults + .gitleaks.toml del consumidor ({n_consumer} allowlist(s)) "
           f"+ central ({n_central} allowlist(s))")
    except Exception as exc:  # noqa: BLE001 — nunca romper el scan
        gh("warning", "Gitleaks config",
           f"No se pudo componer la config ({exc}). Se usa la config central sin cambios.")
        shutil.copyfile(args.central, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
