# Contribuir a pipelines-centrales

Este repo expone workflows reutilizables de seguridad consumidos por +30 repos
de SIMON Movilidad. Un cambio aquí impacta a todos. Por eso seguimos un flujo
estricto y convenciones consistentes con el equipo DevOps.

---

## Modelo de ramas

```
   feature/<nombre>    ─┐
   fix/<bug>            │
   chore/<tarea>        │
   docs/<tema>          ├──▶ develop ──▶ uat ──▶ main
   refactor/<área>      │    (integ)    (stage)  (prod)
   perf/<área>          │
   ci/<cambio>          │
   test/<área>          │
   style/<área>        ─┘
```

| Rama | Propósito | Recibe PRs desde |
|------|-----------|------------------|
| `main` | Lo que los repos consumidores referencian en `@main` o `@vX.Y.Z` | **solo** `uat` |
| `uat` | Staging — workflows validados antes de pasar a producción | **solo** `develop` |
| `develop` | Integración continua | **solo** ramas con prefijo Conventional Commits (ver abajo) |
| `feature/<nombre>` | Nueva funcionalidad | — |
| `fix/<bug>` | Corrección de bug | — |
| `chore/<tarea>` | Mantenimiento (dependencias, config, cleanup) | — |
| `docs/<tema>` | Solo documentación | — |
| `refactor/<área>` | Reorganización sin cambio funcional | — |
| `perf/<área>` | Optimización de tiempo/recursos | — |
| `ci/<cambio>` | Cambios en CI propia del repo | — |
| `test/<área>` | Pruebas | — |
| `style/<área>` | Cambios de formato (whitespace, comillas) | — |

El workflow [`.github/workflows/validate-pr-source.yml`](.github/workflows/validate-pr-source.yml)
enforce automáticamente este flujo. Un PR con source inválido se rechaza con un
comentario explicativo.

---

## Convenciones de commit (Conventional Commits)

Todo commit debe empezar con uno de estos prefijos:

| Prefijo | Cuándo usar | Ejemplo |
|---------|-------------|---------|
| `feat:` | Nueva funcionalidad | `feat: add sec-trivy-image workflow` |
| `fix:` | Corrección de bug | `fix: handle empty SARIF in sec-sast-QG` |
| `chore:` | Mantenimiento sin impacto funcional | `chore: bump gitleaks docker image to v8.18.4` |
| `docs:` | Solo documentación | `docs: clarify NVD_API_KEY setup in README` |
| `test:` | Pruebas / validaciones CI | `test: add yamllint to pre-commit` |
| `refactor:` | Reorganización sin cambio funcional | `refactor: extract HTML template to shared script` |
| `perf:` | Optimización de tiempo/recursos | `perf: cache trivy DB across runs` |
| `ci:` | Cambios en CI propia del repo | `ci: add validate-pr-source enforce` |

**Reglas:**
- Una sola línea de título, < 72 caracteres, en imperativo, en inglés o español
  (consistente con el resto del repo).
- Si el cambio es breaking para los consumidores, añade `!` antes de `:` y
  describe el breaking change en el cuerpo del commit. Ejemplo: `feat!: rename input nvd-api-key to NVD_API_KEY (#42)`.

---

## Flujo de trabajo paso a paso

### 1. Clonar y configurar pre-commit local (una sola vez)

```bash
git clone https://github.com/DevSecOpsSM/pipelines-centrales.git
cd pipelines-centrales

# Instalar pre-commit (requiere Python 3.10+)
pip install pre-commit

# Activar hooks en este repo
pre-commit install
```

A partir de aquí, cada `git commit` corre actionlint, yamllint y los demás
hooks automáticamente sobre los archivos staged. Si fallan, el commit se aborta
y se te muestra qué arreglar.

Para correr los hooks sobre todo el repo manualmente:

```bash
pre-commit run --all-files
```

### 2. Crear rama desde `develop`

```bash
git checkout develop
git pull origin develop
git checkout -b feature/agregar-sonar-quality-gate
# o
git checkout -b fix/sca-timeout-when-no-deps
```

### 3. Hacer cambios + commits convencionales

```bash
git add .github/workflows/sec-sonarqube.yml
git commit -m "feat: enforce quality gate threshold from SonarQube response"
```

### 4. Push y abrir PR a `develop`

```bash
git push -u origin feature/agregar-sonar-quality-gate
gh pr create --base develop --title "feat: enforce quality gate threshold from SonarQube response"
```

### 5. Revisión y merge

- El PR es revisado por el(los) `CODEOWNERS` correspondiente(s).
- `validate-pr-source` debe pasar (target = `develop`, source = `feature/*`).
- Todos los checks de CI deben pasar.
- Al mergear, el cambio queda en `develop`.

### 6. Promoción a `uat` y `main`

La promoción `develop → uat → main` la hace el owner del repo (no un dev
individual). Cada salto es un PR con todo el cambio acumulado y un tag SemVer
cuando llega a `main`.

---

## Reglas inquebrantables

1. **Cero configuración extra en repos consumidores.** Ningún cambio puede
   exigir que los +30 repos cliente añadan secrets, tokens, licencias o PATs
   (excepto los ya documentados: `NVD_API_KEY` opcional, `SONAR_TOKEN`
   obligatorio para SonarQube).
2. **Pin de versiones.** Actions de terceros con tag específico (`@v5`, `@v1.7.7`),
   nunca `@main`. Imágenes Docker con tag específico
   (`zricethezav/gitleaks:v8.18.4`), nunca `:latest`.
3. **Modo auditoría en pasos de escaneo.** Todas las herramientas corren con
   `continue-on-error: true` para no romper el pipeline del consumidor.
   El bloqueo lo aplica únicamente el job `quality-gate` final.
4. **Reportes nativos.** Reporte HTML generado con Python inlineado o plantilla
   nativa de la herramienta (Trivy `@/contrib/html.tpl`). No usar acciones de
   terceros tipo `sarif-to-html-action`.
5. **Conventional Commits** obligatorio para que el changelog se pueda generar
   automáticamente.
6. **No mergeear con conflictos.** Resolverlos en local rebasing contra la rama
   target antes de empujar.

---

## Antes de pedir review

- [ ] `pre-commit run --all-files` pasa
- [ ] `actionlint` no reporta problemas en los workflows tocados
- [ ] El PR tiene un título Conventional Commit válido
- [ ] El cuerpo del PR está completo (plantilla rellenada)
- [ ] Si añadiste un input nuevo a un workflow reutilizable, actualizaste
  `examples/seguridad.yml` y la tabla de adopción en `README.md`
- [ ] Si hay impacto en consumidores, lo marcaste explícitamente en el PR

---

## Reportar bugs / proponer mejoras

Abre un issue con la plantilla correspondiente:

- 🐛 [Bug en un workflow reutilizable](.github/ISSUE_TEMPLATE/bug_report.md)
- ✨ [Propuesta de mejora o nueva herramienta](.github/ISSUE_TEMPLATE/feature_request.md)

Si reportas una **vulnerabilidad de seguridad** que afecte a los consumidores,
usa el canal privado (Security Advisory) — no abras un issue público.

---

**Equipo Cybersecurity** · SIMON Movilidad
