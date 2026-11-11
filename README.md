<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-->

# autz

Headless broken-access-control detector — finds IDOR, BOLA, and privilege-escalation seams by diffing the same request across multiple identities. MIT. Rust · async · zero GUI.

**English** · [Español](#español)

---

## What it does

Template-matching scanners (nuclei and most DAST tools) are blind to authorization flaws by design: they look for payload patterns, not for who is asking. autz takes a different approach — it sends the same request under several identities and flags every seam where one identity receives access that should be denied.

### The predicate

A correct access-control layer answers **404 — never 403** to a resource the caller does not own. From that, the detection rule follows:

> If an identity that is **not** the resource owner receives a **200 with the same body** as the owner, that identity obtained the resource — there is a seam.

autz handles the most common false positive: each identity seeing *its own* profile endpoint at `/api/me` returns 200 with different bodies, which is not a leak. Findings are reported with a **confidence level**: `High` (identical body signature after normalizing reflected credentials) or `Medium` (only the length matches — the uncertainty is stated, not hidden).

### What it detects

| Seam | Description | CWE |
|---|---|---|
| `HorizontalIdor` | A peer obtains the owner's resource (IDOR / BOLA). | CWE-639 |
| `VerticalPrivEsc` | A lower-privilege identity reaches a higher-privilege function. | CWE-285 |
| `UnauthLeak` | An unauthenticated caller obtains a protected resource. | CWE-862 |

In addition, **401/403 bypass detection** (`is_bypass` + `observe_evasion`): known bypass techniques are tried against a protected endpoint (IP-spoof headers, `X-Original-URL`, path suffixes, verb tampering); a 2xx response with real content is flagged.

### Design

- **Pure where possible.** The classifier, bypass probe, body normalizer, and ban-signal detector are pure functions — testable without a network or live credentials.
- **No harmful writes.** The driver issues only GET requests (and POST solely as a bypass technique, never destructive writes).
- **The caller owns anti-ban.** autz does not decide pacing, does not persist state, and does not retry on rate-limit: it returns the seams found and a rate-limit signal. Backoff, circuit-breaking, and persistence belong in the orchestrator.

### Evidence

Extracted from a production access-control orchestrator as a standalone, reusable crate. The classification logic was validated by simulation over **120 endpoints**: 0 false positives, 0 false negatives.

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it is not distributed through crates.io.

This is not abandonment, not an incident, and there was no breach. It is a decision, and it is worth saying what it rests on. Through 2026 the package registries and code-hosting platforms were hit by sustained, chained supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious extensions that exfiltrated thousands of private repositories. For a security tool designed to detect authorization flaws in production systems, hosting the source there stopped being a neutral decision.

**The licence has not changed and the code is still available to anyone who asks** — delivered with a signature and a checksum, at no cost, with no NDA, no restriction on what you publish about it, and no expiry.

To request it: **[xiliux.com](https://xiliux.com)**

---

## Español

## Qué hace

Los escáneres por plantillas (nuclei y la mayoría de las herramientas DAST) son ciegos a los fallos de autorización por diseño: buscan patrones en el payload, no en quién pregunta. autz adopta un enfoque distinto: envía la misma petición bajo varias identidades y señala cada costura donde una identidad recibe un acceso que debería negársele.

### El predicado

Un control de acceso correcto responde **404 — nunca 403** a un recurso que el llamante no posee. De ahí se desprende la regla de detección:

> Si una identidad que **no** es la dueña del recurso recibe un **200 con el mismo cuerpo** que la dueña, esa identidad obtuvo el recurso — hay una costura.

autz maneja el falso positivo más frecuente: cada identidad viendo su propio perfil en `/api/me` devuelve 200 con cuerpos distintos, lo que no es una fuga. Los hallazgos se reportan con un nivel de **confianza**: `Alta` (firma de cuerpo idéntica tras normalizar las credenciales reflejadas) o `Media` (solo coincide la longitud — la incertidumbre se indica, no se oculta).

### Qué detecta

| Costura | Descripción | CWE |
|---|---|---|
| `IdorHorizontal` | Un par obtiene el recurso del dueño (IDOR / BOLA). | CWE-639 |
| `PrivEscVertical` | Una identidad de menor privilegio alcanza una función de mayor privilegio. | CWE-285 |
| `FugaSinAuth` | Un llamante no autenticado obtiene un recurso protegido. | CWE-862 |

Además, **detección de bypass de 401/403** (`es_bypass` + `observar_evasion`): se prueban técnicas conocidas contra un endpoint protegido (cabeceras de suplantación de IP, `X-Original-URL`, sufijos de ruta, cambio de verbo); una respuesta 2xx con contenido real queda marcada.

### Diseño

- **Puro donde puede.** El clasificador, la sonda de bypass, el normalizador de cuerpo y el detector de señal de baneo son funciones puras — testeables sin red ni credenciales reales.
- **Sin escrituras dañinas.** El driver solo emite peticiones GET (y POST únicamente como técnica de bypass, nunca escrituras destructivas).
- **El llamante gestiona el anti-baneo.** autz no decide pausas, no persiste estado ni reintenta ante rate-limit: devuelve las costuras encontradas y la señal de rate-limit. El backoff, el cortacircuitos y la persistencia son responsabilidad del orquestador.

### Evidencia

Extraído de un orquestador de control de acceso en producción como crate independiente y reutilizable. La lógica de clasificación fue validada por simulación sobre **120 endpoints**: 0 falsos positivos, 0 falsos negativos.

### El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni se distribuye por crates.io.

No es abandono ni un incidente: es una decisión, y conviene decir por qué. A lo largo de 2026 los registros de paquetes y las plataformas de código han sufrido ataques encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto, extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar aquí el código de una herramienta de seguridad diseñada para detectar fallos de autorización en sistemas en producción dejó de ser una decisión neutra.

**La licencia no cambia y el código se sigue entregando a quien lo pida**, con su firma y su suma de verificación, sin coste, sin NDA, sin restricción sobre lo que publique y sin caducidad.

Para solicitarlo: **[xiliux.com](https://xiliux.com)**

---

*autz* — © 2026 Juan Carlos Isaza. Licencia **MIT**.
La licencia no cambia: lo que cambia es por dónde se entrega el código.
