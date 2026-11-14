<!-- SPDX-License-Identifier: MIT -->
# autz

Motor **headless** de detección de **control de acceso roto** — IDOR / BOLA / BAC
y evasión de 401/403 — por **diffing de respuestas entre identidades**. Lógica
pura + driver HTTP; sin GUI, sin orquestador, sin estado global.

Es lo que un emparejador de plantillas (nuclei, la mayoría de los DAST) **no ve
por diseño**: los fallos de autorización dependen de *quién* pide, no de un
payload. `autz` compara la MISMA petición vista por varias identidades y marca la
costura donde se concede un acceso que debería negarse.

## El predicado

Sale de una metodología **defensiva**, invertida: un control de acceso correcto
responde **404 —nunca 403—** al recurso ajeno. Luego, como detector:

> si una identidad que **no** es dueña del recurso recibe **200 con el mismo
> cuerpo** que la dueña, obtuvo el recurso → hay costura.

Discrimina el mayor falso positivo (cada identidad viendo **lo suyo** en `/api/me`
da 200 con cuerpos distintos → no es fuga) y reporta con **confianza**: `Alta`
(firma de cuerpo idéntica, tras normalizar lo reflejado de la credencial) o
`Media` (solo coincide la longitud — se marca la incertidumbre, no se esconde).

## Qué detecta

| Costura | Qué es | CWE |
|---|---|---|
| `IdorHorizontal` | un par obtiene el recurso del dueño (IDOR/BOLA) | CWE-639 |
| `PrivEscVertical` | menor privilegio alcanza una función mayor | CWE-285 |
| `FugaSinAuth` | sin autenticar se obtiene el recurso protegido | CWE-862 |

Más **evasión de 401/403** (`es_bypass` + `observar_evasion`): a un endpoint
protegido se le prueban técnicas conocidas (IP-spoof headers, `X-Original-URL`,
sufijos de ruta, cambio de verbo); si una devuelve 2xx con contenido real, se
saltó el control.

## Uso

```rust
use autz::{cliente, diffear, Identidad, Papel, Solicitud, UMBRAL_DEFECTO};

let client = cliente("mi-agente").unwrap(); // no sigue redirecciones a propósito
let ids = vec![
    Identidad { papel: Papel::Dueno, cabeceras: vec![("Cookie".into(), "s=alice".into())] },
    Identidad { papel: Papel::Par,   cabeceras: vec![("Cookie".into(), "s=bob".into())] },
];
let sol = Solicitud { url: "https://api.ejemplo.com/orders/42".into() };
let (costuras, vio_ratelimit) = diffear(&client, &sol, &ids, UMBRAL_DEFECTO).await?;
// `vio_ratelimit` = 429/503: el consumidor aplica su backoff/cortacircuitos.
```

## Filosofía

- **Puro donde puede.** `clasificar`, `es_bypass`, `firma_normalizada`,
  `es_senal_de_baneo` son funciones puras, testeables sin red ni credenciales.
- **Sin daño.** El driver solo hace GET (y POST como técnica de evasión, nunca
  escrituras destructivas).
- **El consumidor manda el anti-baneo.** El motor NO decide pausas ni persiste
  nada: devuelve las costuras y la señal de rate-limit; la orquestación (pacing,
  cortacircuitos, persistencia) vive en quien lo usa.

## Estado

Extraído de un orquestador de bug bounty (nexus) como pieza reutilizable. La
lógica está validada por simulación en el consumidor: 0 falsos positivos y 0
falsos negativos sobre 120 endpoints. Vendorizado / consumido por ruta; no se
publica en un registro sin decisión aparte.

## Licencia

MIT © 2026 Isaza Arenas. Ver `LICENSE` y `NOTICE`.
