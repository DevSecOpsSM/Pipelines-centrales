---
name: 🐛 Bug en un workflow reutilizable
about: Reporta un fallo o comportamiento incorrecto en un workflow `sec-*.yml`
title: "[BUG] <workflow afectado>: <descripción corta>"
labels: ["bug", "needs-triage"]
assignees: []
---

## Workflow afectado

<!-- Selecciona el workflow donde ocurre el fallo. -->

- [ ] `sec-hooks.yml`
- [ ] `sec-secrets.yml` / `sec-secrets-QG.yml`
- [ ] `sec-sast-QG.yml`
- [ ] `sec-sca.yml`
- [ ] `sec-containers.yml` / `sec-containers-QG.yml`
- [ ] `sec-iac-terraform.yml`
- [ ] `sec-sonarqube.yml`
- [ ] `validate-pr-source.yml`
- [ ] Otro: <!-- nombre del archivo -->

## Repo consumidor donde ocurre

<!-- URL del repo donde se reproduce. Si es interno y no puedes compartir URL,
     indica al menos: lenguaje, tipo de proyecto, tamaño aprox. -->

- Repo:
- Lenguaje principal:
- Workflow run URL:

## Comportamiento observado

<!-- Qué pasó. Pega aquí el error / output relevante (no secretos). -->

```
<pega aquí el log>
```

## Comportamiento esperado

<!-- Qué debería haber pasado. -->



## Pasos para reproducir

<!-- Si es replicable. Si es intermitente, descríbelo. -->

1.
2.
3.

## Frecuencia

- [ ] Siempre falla
- [ ] Intermitente
- [ ] Solo en este repo
- [ ] En múltiples repos

## Versión / commit de pipelines-centrales

<!-- Tag o commit SHA referenciado en el `uses:` del repo consumidor.
     Ejemplo: pipelines-centrales/.github/workflows/sec-sast-QG.yml@v1.0.0 -->



## Contexto adicional

<!-- Logs, screenshots, configuración relevante. -->
