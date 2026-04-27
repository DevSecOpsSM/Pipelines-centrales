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

*(Inserta aquí la imagen de tu diagrama)*
![Diagrama de Arquitectura DevSecOps](docs/diagrama_arquitectura.jpg)

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

## Características de diseño

- **Cero configuración extra**: ningún repositorio cliente necesita tokens SaaS, licencias ni PATs
- **Modo auditoría**: `continue-on-error: true` en todos los pasos — reporta sin bloquear
- **Reportes HTML nativos**: generados con Python inlineado, sin dependencias de terceros
- **Carpeta por repositorio**: los artefactos se organizan como `reports/{nombre-repo}/`
- **Fix NVD 429**: caché semanal de la base de datos NVD + delay de 6s entre peticiones
- **Trivy HTML**: plantilla descargada vía `curl` para evitar errores de path en Docker
- **Gitleaks sin licencia**: usa `zricethezav/gitleaks:latest` directamente, NO la acción oficial

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
