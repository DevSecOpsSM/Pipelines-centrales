# pipelines-centrales

Repositorio central de pipelines de seguridad SSDLC para la organización.
Los repositorios de aplicaciones consumen estos workflows reutilizables sin necesidad de configuración adicional.

## Arquitectura

```
pipelines-centrales/                    ← Este repositorio (Internal)
├── .github/workflows/
│   ├── sec-hooks.yml                   ← Etapa 0: Pre-commit hooks
│   ├── sec-secrets.yml                 ← Etapa 1: Gitleaks + TruffleHog
│   ├── sec-sast.yml                    ← Etapa 2: Semgrep OWASP Top 10
│   ├── sec-sca.yml                     ← Etapa 3: OWASP Dependency-Check
│   └── sec-containers.yml              ← Etapa 4: KICS + Hadolint + Trivy
├── report-templates/                   ← Scripts Python de referencia
│   ├── gitleaks_report.py
│   ├── trufflehog_report.py
│   ├── semgrep_report.py
│   ├── kics_report.py
│   └── hadolint_report.py
└── examples/
    └── seguridad.yml                   ← Archivo consumidor de ejemplo
```
---

## 🏛️ Arquitectura del Sistema

La estrategia se basa en el principio de **Shift Left** (desplazar la seguridad a la izquierda), detectando vulnerabilidades en el mismo momento en que el desarrollador hace un *Push* o *Pull Request*.



### Componentes de la Arquitectura:
1. **App Repo (El Disparador):** El repositorio del proyecto invoca los flujos de este repositorio central.
2. **Pipelines Centrales (Motores de Análisis):** Se ejecutan herramientas líderes de la industria en formato "offline" y "auditoría".
3. **Motor de Procesamiento (Python):** Estandariza los resultados crudos de las herramientas en reportes útiles.
4. **Remediación (Salidas):** Genera Issues automatizados para desarrolladores y reportes PDF para auditores.

---
## Herramientas por etapa (SSDLC)

| Etapa | Workflow | Herramientas | Propósito |
|-------|----------|-------------|-----------|
| 0 | `sec-hooks.yml` | pre-commit | Validaciones básicas pre-commit |
| 1 | `sec-secrets.yml` | Gitleaks (Docker) · TruffleHog | Detección de secretos expuestos |
| 2 | `sec-sast.yml` | Semgrep | SAST multi-lenguaje OWASP Top 10 |
| 3 | `sec-sca.yml` | OWASP Dependency-Check | CVEs en dependencias (SCA) |
| 4 | `sec-containers.yml` | KICS · Hadolint · Trivy | Seguridad IaC y contenedores |

## Modelo de ramas

Este repo sigue el branch model estándar del equipo DevOps de SIMON. Cambios
nuevos llegan vía `feature/*` o `fix/*` y avanzan en línea recta:

```
feature/*  ─┐
fix/*      ─┴──▶ develop ──▶ uat ──▶ main
                  (integ)    (stage)   (prod / consumido por los repos cliente)
```

| Rama destino | Acepta PRs solo desde |
|--------------|-----------------------|
| `main` | `uat` |
| `uat` | `develop` |
| `develop` | `feature/*` o `fix/*` |

El workflow [`validate-pr-source.yml`](.github/workflows/validate-pr-source.yml)
enforce este modelo automáticamente. Cualquier PR con source inválido es
rechazado con un comentario explicativo.

Los repos consumidores referencian este repo con `@main` (versión rolling) o
`@vX.Y.Z` (versión pinned) — el ref **siempre** debe apuntar a un commit
mergeado en `main`.

## Cómo contribuir

Antes de abrir un PR:

1. Lee [CONTRIBUTING.md](CONTRIBUTING.md) — convenciones de commit
   (Conventional Commits), flujo de ramas, reglas inquebrantables.
2. Instala los hooks locales:
   ```bash
   pip install pre-commit
   pre-commit install
   ```
3. Abre el PR contra `develop` desde una rama `feature/*` o `fix/*`.

Toda PR pasa por:
- ✅ `validate-pr-source` — enforce del branch model
- ✅ Revisión de [CODEOWNERS](.github/CODEOWNERS)
- ✅ Checks de actionlint + yamllint (vía pre-commit)

## Cómo usar en un repositorio de aplicación

Copia el archivo [examples/seguridad.yml](examples/seguridad.yml) a `.github/workflows/seguridad.yml` en tu repositorio:

```yaml
jobs:
  secretos:
    uses: MiOrg/pipelines-centrales/.github/workflows/sec-secrets.yml@main

  sast:
    uses: MiOrg/pipelines-centrales/.github/workflows/sec-sast.yml@main

  sca:
    uses: MiOrg/pipelines-centrales/.github/workflows/sec-sca.yml@main
    secrets:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}  # opcional

  contenedores:
    uses: MiOrg/pipelines-centrales/.github/workflows/sec-containers.yml@main
```

## Triage de hallazgos y falsos positivos

### Principio: triage humano antes de accionar

Los hallazgos de **secretos** y de **autorización** se revisan antes de abrir
trabajo de remediación (rotar credenciales, refactorizar controllers). Las
reglas que los producen son ruidosas por diseño:

- `generic-api-key` (Gitleaks) marca cualquier valor de alta entropía asignado
  a algo cuyo nombre contiene `key`, `token`, `secret`… sin saber si es una
  credencial.
- `missing-or-broken-authorization` (Semgrep) solo busca el atributo
  `[Authorize]` en la clase; no ve middleware ni filtros globales.

Antes de escalar un hallazgo de estas reglas, el equipo de Ciberseguridad
confirma que es real. Si resulta falso positivo, se corrige en el origen
(allowlist de Gitleaks o `.security/authz.yml`, ver abajo) en lugar de
ignorarlo en cada reporte.
Un hallazgo es un indicio que hay que verificar, no un veredicto.

> Caso que motivó esta guía (Atenea / Agendamiento): GUIDs de configuración
> reportados como "secretos hardcodeados P1", 1.828 JWT expirados en logs
> versionados y 3 controllers marcados "sin autorización" que estaban
> protegidos por un middleware propio. Ninguno requería rotación ni refactor.

### Gitleaks — configuración central y allowlist

`sec-secrets.yml` compone la configuración en cada ejecución:

```
reglas por defecto de Gitleaks
  + .gitleaks.toml del repo consumidor (si existe): sus reglas y excepciones
  + allowlists centrales de config/gitleaks.toml (siempre)
```

El repo consumidor **puede añadir** reglas y excepciones propias, pero **no puede
quitar** cobertura: si su `.gitleaks.toml` desactiva las reglas por defecto
(`useDefault = false`), usa `disabledRules` o `extend.path`, esos campos se
ignoran y el job lo indica con un `::warning`. No se usa el `[extend]` nativo
porque Gitleaks descarta las `[[allowlists]]` del config padre (detalle en
[scripts/gitleaks_compose_config.py](scripts/gitleaks_compose_config.py)).

Excepciones centrales vigentes ([config/gitleaks.toml](config/gitleaks.toml)):

| ID | Regla | Falso positivo | Sigue alertando |
|----|-------|----------------|-----------------|
| FP-01 | `generic-api-key` | `Key` / `ConfigKey` / `ConfigurationKey` `= "<GUID>"`: clave de registro en tablas de configuración .NET | `ApiKey`, `SecretKey`, `x.Key`… `= "<GUID>"` (hay API keys reales con formato GUID) |
| FP-01b | `generic-api-key` | Solo en `.sql`: `key = '<GUID>'` (columna `key` de la tabla de configuración en scripts de datos) | `api_key`, `secret_key`… en SQL; `key = '<uuid>'` fuera de `.sql` |
| FP-02 | `jwt` | JWT en logs versionados (`log20240115.txt`, `logs/*.txt`, `*.log`) | Cualquier otro secreto dentro de un log (AWS keys, connection strings…) |

#### Política de allowlist: toda excepción requiere justificación

La allowlist central se aplica a **todos** los repos consumidores en cuanto se
mergea a `main`. Cada excepción reduce la cobertura de la organización entera y,
si se escribe mal, puede ocultar un secreto real sin que nadie lo note. Por eso:

1. **Se exige evidencia.** La excepción nace de falsos positivos confirmados en
   triage en al menos un repo real (se cita en el PR), no de una suposición.
2. **El alcance es mínimo.** Siempre `targetRules` con la regla concreta;
   nunca allowlists globales. Se prefiere `regexTarget = "match"` anclado
   (`^...$`) sobre `paths`, y `paths` específicos sobre comodines.
   Contraejemplo: `.*log.*\.txt$` también silenciaría `login.txt` o `catalog.txt`.
3. **Cada excepción se documenta en el toml:** qué falso positivo cubre, por qué
   es seguro, qué sigue alertando y qué riesgo residual se acepta.
4. **Se prueba en los dos sentidos.** El PR muestra que el falso positivo se
   silencia **y** que un secreto real parecido sigue detectándose
   (`gitleaks git <repo-prueba> --config config/gitleaks.toml`).
5. **Revisa Ciberseguridad.** `config/gitleaks.toml` está en
   [CODEOWNERS](.github/CODEOWNERS); para que esto obligue de verdad, la
   protección de `main` debe tener activo *Require review from Code Owners*.
6. **Ante la duda, no se silencia.** Un falso positivo cuesta minutos de
   triage; un secreto real silenciado puede costar un incidente reportable a la
   SIC (Ley 1581).

Un falso positivo **puntual**, que no generaliza a un patrón, no va en la
allowlist central: se registra en el `.gitleaksignore` del repo consumidor por
fingerprint (columna `Fingerprint` del `gitleaks-raw.json`), con un comentario:

```
# Falso positivo revisado por <persona>, <fecha>: <motivo>
a1b2c3d4...:src/Seed.cs:generic-api-key:42
```

#### Recomendación para repos consumidores: no versionar logs

FP-02 evita que los JWT en logs inflen el reporte, pero el problema de fondo
sigue ahí: **los logs no deben estar en el repo** (pueden contener PII y otros
secretos que sí se reportarán). Añade a tu `.gitignore`:

```gitignore
# Logs de aplicación (Serilog/NLog rolling files)
log*.txt
logs/
*.log
```

Y retira del índice los que ya están versionados: `git rm --cached <archivos>`.
Ojo: siguen en el historial. Si contienen PII o credenciales vigentes, se trata
como incidente (rotación y, si aplica, limpieza del historial).

### Semgrep — límite de la autorización por middleware

La regla `missing-or-broken-authorization` (C#/.NET, incluida en el ruleset
`p/owasp-top-ten`) reporta todo `Controller` que no tenga en la clase
`[Authorize]`, `[Authorize(Roles/Policy = …)]` o `[AllowAnonymous]`. **No
detecta** autorización aplicada por:

- middleware propio (p. ej. `AteneaIdentityMiddleware`, secure-by-default:
  protege todo salvo lo marcado `[AllowAnonymous]`),
- filtros globales (`options.Filters.Add(new AuthorizeFilter())`),
- `FallbackPolicy` / `RequireAuthorization()` en el mapeo de endpoints.

Su severidad nativa es `INFO`, que el pipeline mapea a `low`. Un solo hallazgo
no bloquea, pero cuenta para el umbral acumulado de `low` del consolidador
(> 20). **Una API .NET secure-by-default con más de 20 controllers bloquea su
propio release solo con falsos positivos.**

**En proyectos con middleware o filtros de autorización propios, estos
hallazgos requieren verificación manual** y no se tratan como confirmados sin
revisar el código.

#### Declarar y verificar: `.security/authz.yml`

Un repo con middleware de autorización propio puede **declararlo**. El pipeline
lo **verifica** antes de aceptarlo: una declaración sin verificación no tiene efecto.

1. El repo crea `.security/authz.yml` (ejemplo:
   [examples/security-authz.yml](examples/security-authz.yml)). Llega por PR,
   así que queda revisado y auditado.
2. `sec-sast.yml` genera una regla Semgrep con el nombre declarado y comprueba
   que el middleware está registrado con `app.UseMiddleware<X>()`,
   `app.UseMiddleware(typeof(X))` o un método de extensión del mismo proyecto
   que los llame (`app.AddIdentityMiddleware()`) **antes** de `MapControllers()` /
   `MapControllerRoute()` / `MapDefaultControllerRoute()` / `UseEndpoints()`,
   **en el mismo bloque**. Un registro dentro de un `if` no verifica.
3. Si verifica, los hallazgos `missing-or-broken-authorization` del **mismo
   proyecto `.csproj`** que el registro (o de los `scope` declarados) pasan a
   **"cubiertos por middleware"**: siguen en el reporte HTML, en su propia
   sección, pero **no suman al quality gate**.
4. Además se genera el **inventario de `[AllowAnonymous]`** (atributo de clase o
   de método, y `.AllowAnonymous()` en minimal APIs). En secure-by-default, esa
   lista es la superficie expuesta real y se revisa en cada release.

Esquema (v1, estricto: una clave desconocida invalida el archivo):

| Campo | Obligatorio | Significado |
|-------|-------------|-------------|
| `version` | sí | Siempre `1` |
| `middleware` | sí | Lista no vacía de middlewares de autorización |
| `middleware[].name` | sí | Nombre de la clase C#, identificador simple sin namespace (`AteneaIdentityMiddleware`) |
| `middleware[].justification` | sí (≥ 20 caracteres) | Por qué cubre la autorización y cuál es su modelo (p. ej. secure-by-default + `[AllowAnonymous]`) |
| `middleware[].scope` | no | Rutas, relativas a la raíz, cuyos controllers cubre. Por defecto, el proyecto (`.csproj`) donde se verificó el registro. Úsese solo si los controllers viven en otro proyecto |

**Fail-closed.** En cualquiera de estos casos ningún hallazgo se reclasifica, todos
cuentan normal y el job muestra un `::warning` (más el estado en rojo en el
reporte HTML):

| Estado | Causa |
|--------|-------|
| `invalid` | YAML mal formado, clave desconocida, nombre no válido, justificación corta, `scope` fuera del repo |
| `not_verified` | Declarado, pero no se encontró el registro antes del mapeo de controllers |
| `partial` | Varios middlewares declarados y alguno no verifica: solo cuentan como cubiertos los controllers de los que sí |
| `error` | Fallo al ejecutar la verificación o script central no disponible |

**Lo que la verificación NO cubre** y sigue siendo revisión manual:

1. que el middleware **aplique correctamente** la autorización (su lógica),
2. exclusiones por path (`UseWhen`, listas de rutas públicas) sin
   `[AllowAnonymous]` explícito,
3. métodos de extensión definidos en **otro** proyecto (p. ej. una librería
   compartida). Sí se aceptan las extensiones del mismo proyecto
   (`app.AddIdentityMiddleware()` → `MiddlewareRegistration.cs`, el patrón de
   Atenea), siempre que su cuerpo llame a `UseMiddleware<X>()` como sentencia
   directa, sin `if`/`else`/`switch`/bucles/lambdas,
4. que cada `[AllowAnonymous]` del inventario esté justificado.

> Si los repos .NET de la organización resultan usar el mismo middleware, el
> paso natural es convertir la declaración en una regla central (sin archivo
> por repo). El script ya está parametrizado por nombre, así que no hay que
> rehacerlo.

## Configuración de la organización GitHub (pasos únicos)

Estos pasos se realizan **una sola vez** por el administrador de la organización:

### 1. Configurar este repositorio como "Internal"

```
GitHub → MiOrg/pipelines-centrales → Settings → General
→ Change repository visibility → Internal
```

Esto permite que cualquier repositorio de la organización acceda a los workflows
usando el GITHUB_TOKEN estándar, sin tokens adicionales.

### 2. Habilitar el uso de workflows reutilizables entre repositorios

```
GitHub → MiOrg (Organización) → Settings → Actions → General
→ "Allow all actions and reusable workflows"
  O bien: "Allow MiOrg, and select non-MiOrg, actions and reusable workflows"
  y añadir: MiOrg/pipelines-centrales
```

### 3. (Recomendado) Registrar NVD_API_KEY como secreto organizacional

El API Key de NVD es gratuito y elimina el rate-limit que causaba el timeout de 6h en Dependency-Check.

```
1. Registrarse en: https://nvd.nist.gov/developers/request-an-api-key
2. GitHub → MiOrg → Settings → Secrets and variables → Actions
   → New organization secret → Nombre: NVD_API_KEY
   → Repository access: All repositories
```

Una vez configurado, todos los repositorios pueden usar:
```yaml
secrets:
  NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
```

### 4. (Opcional) Permisos de GITHUB_TOKEN

Si los repositorios son privados y hay problemas de acceso:

```
GitHub → MiOrg → Settings → Actions → General
→ Workflow permissions → "Read repository contents and packages permissions"
```

Esto es suficiente para workflows reutilizables con repositorios Internal.

### 5. (Obligatorio) Exigir revisión de CODEOWNERS en `main`

[CODEOWNERS](.github/CODEOWNERS) protege la allowlist central de Gitleaks
(`config/gitleaks.toml`) y los scripts que deciden qué hallazgos dejan de
contar en el gate. **Sin esta protección activa, CODEOWNERS solo sugiere
revisores y no bloquea nada.**

```
GitHub → MiOrg/pipelines-centrales → Settings → Branches (o Rules → Rulesets)
→ regla de protección de main
→ ✅ Require a pull request before merging
→ ✅ Require review from Code Owners
```

Verificación: abrir un PR que toque `config/gitleaks.toml` y confirmar que
GitHub pide la aprobación del owner antes de permitir el merge.

## Características de diseño

- **Cero configuración extra**: ningún repositorio cliente necesita tokens SaaS, licencias ni PATs
- **Modo auditoría**: `continue-on-error: true` en todos los pasos — reporta sin bloquear
- **Reportes HTML nativos**: generados con Python inlineado, sin dependencias de terceros
- **Carpeta por repositorio**: los artefactos se organizan como `reports/{nombre-repo}/`
- **Fix NVD 429**: caché semanal de la base de datos NVD + delay de 6s entre peticiones
- **Trivy HTML**: plantilla descargada vía `curl` para evitar errores de path en Docker
- **Gitleaks sin licencia**: usa la imagen `zricethezav/gitleaks` (fijada por versión + digest) directamente, NO la acción oficial

## Artefactos generados

Cada pipeline sube los reportes como GitHub Actions Artifacts (retención: 30 días):

| Artifact | Contenido |
|----------|-----------|
| `security-hooks-report` | `{repo}/kicks-report.html` |
| `security-secrets-gitleaks` | `{repo}/gitleaks-report.html` |
| `security-secrets-trufflehog` | `{repo}/trufflehog-report.html` |
| `security-sast-semgrep` | `{repo}/semgrep-report.html` |
| `security-sca-dependency-check` | `{repo}/dependency-check-report.html` |
| `security-containers-kics` | `{repo}/kics-report.html` |
| `security-containers-hadolint` | `{repo}/hadolint-report.html` |
| `security-containers-trivy` | `{repo}/trivy-fs-report.html` + `trivy-image-report.html` |

---

**Equipo Cybersecurity** · Simon Movilidad
