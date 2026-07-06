---
name: ✨ Propuesta de mejora o nueva herramienta
about: Proponer nueva herramienta, regla de Quality Gate, o cambio funcional
title: "[FEAT] <descripción corta>"
labels: ["enhancement", "needs-triage"]
assignees: []
---

## Tipo de propuesta

- [ ] Nueva herramienta de seguridad en un workflow existente
- [ ] Nuevo workflow `sec-*.yml`
- [ ] Cambio en umbrales de Quality Gate
- [ ] Nuevo input al `workflow_call` de un workflow existente
- [ ] Mejora en el reporte HTML / step summary / comentario en PR
- [ ] Otro: <!-- describe -->

## Motivación

<!-- ¿Qué problema o necesidad resuelve esto?
     ¿Quién se beneficia (equipo de seguridad, devs, auditores)? -->



## Propuesta

<!-- Cómo se vería el cambio. Sé específico.
     Si propones una nueva herramienta, indica:
       - nombre y URL del proyecto
       - licencia
       - lenguajes soportados
       - tipo (SAST, SCA, secrets, IaC, container, etc.)
       - cómo se integraría (Docker, binario, action oficial vs custom) -->



## Alternativas evaluadas

<!-- ¿Qué otras opciones consideraste? ¿Por qué esta y no las otras?
     Esto evita que el revisor tenga que pedir contexto. -->



## Impacto en consumidores

- [ ] No requiere cambios en los repos consumidores
- [ ] Requiere actualizar `seguridad.yml` en los repos consumidores
- [ ] Requiere nuevo secret organizacional
- [ ] Aumenta tiempo de ejecución del pipeline (estimado: <!-- N minutos -->)

## Restricciones del repo a respetar

<!-- Tu propuesta debe cumplir con: -->

- [ ] Cero configuración extra (no tokens SaaS, no licencias, no PATs)
- [ ] Modo auditoría (`continue-on-error: true` en pasos de escaneo)
- [ ] Reporte HTML/step-summary nativo (no acciones de terceros frágiles)
- [ ] Pin de versión (no `:latest`, no `@main`)
- [ ] Universal (no atado a un lenguaje específico, salvo casos justificados)

## Contexto adicional

<!-- Links a documentación, benchmarks, comparativas. -->
