<!--
═══════════════════════════════════════════════════════════════════════════
 Pull Request Template — pipelines-centrales
 Repositorio de workflows reutilizables consumidos por +30 repos de SIMON.
 Antes de mergear, asegúrate de que tu cambio NO rompa a los consumidores.
═══════════════════════════════════════════════════════════════════════════
-->

## Resumen

<!-- Describe en 1-3 frases QUÉ cambia y POR QUÉ. -->



## Tipo de cambio

<!-- Marca la(s) opción(es) que aplican. Sigue Conventional Commits. -->

- [ ] `feat`     — Nueva funcionalidad (nuevo workflow, nueva herramienta, nuevo input)
- [ ] `fix`      — Corrección de bug en un workflow o reporte
- [ ] `chore`    — Tarea de mantenimiento sin impacto funcional
- [ ] `docs`     — Solo documentación (README, CONTRIBUTING, comentarios)
- [ ] `test`     — Pruebas o validaciones en CI
- [ ] `refactor` — Reorganización sin cambio de comportamiento
- [ ] `perf`     — Optimización de tiempo de ejecución o recursos
- [ ] `ci`       — Cambios en infraestructura del propio repo (no en workflows reutilizables)

## Issue relacionado

<!-- Closes #N · Refs #N · N/A si es un cambio menor sin issue. -->



## Cambios principales

<!-- Bullet list de los cambios concretos. Sé específico. -->

-
-
-

## Impacto en repos consumidores

<!-- CRÍTICO: ¿este cambio rompe la interfaz que consumen los repos cliente? -->

- [ ] **No** — cambio interno, los consumidores no necesitan ajustar nada
- [ ] **Sí (breaking)** — los consumidores deben actualizar su `seguridad.yml`. Detalles abajo:

<!-- Si es breaking, lista: qué input cambió, cómo migrar, ejemplo antes/después. -->



## Checklist

### Calidad del cambio
- [ ] `pre-commit run --all-files` pasa sin errores en local
- [ ] `actionlint` no reporta problemas en los workflows modificados
- [ ] No introduzco secretos ni credenciales en código
- [ ] No uso `:latest` en imágenes Docker ni `@main` en actions de terceros

### Compatibilidad
- [ ] Mantiene el contrato `on: workflow_call` para los workflows reutilizables
- [ ] Mantiene la convención `reports/{repo-name}/` para artifacts
- [ ] No requiere configuración adicional en los repos consumidores (cero-config)

### Documentación
- [ ] Actualicé `README.md` si cambió la interfaz pública
- [ ] Actualicé `examples/seguridad.yml` si añadí/cambié inputs
- [ ] Actualicé `CHANGELOG.md` (si aplica versión)

## Validación manual

<!-- Cómo probaste el cambio. Sé específico — runs, repos, comandos. -->

- Workflow run:
- Repo de prueba:
- Resultado:

## Notas adicionales

<!-- Cualquier contexto extra para los revisores. -->
