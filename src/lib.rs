// SPDX-License-Identifier: MIT
//! Motor de detección de CONTROL DE ACCESO roto (IDOR/BOLA/BAC), headless.
//!
//! nuclei no lo ve por diseño: es un emparejador de plantillas SIN estado ni
//! identidad. Esto compara la MISMA petición vista por varias IDENTIDADES y marca
//! la costura donde se concede acceso que debería negarse.
//!
//! El predicado sale de nuestra propia doc DEFENSIVA, invertida
//! (`conocimiento/seguridad_medico_informes.md`): un IDOR bien cerrado responde
//! **404 —nunca 403—** al recurso ajeno. Luego: si una identidad que NO es dueña
//! del recurso recibe 200 con el MISMO cuerpo que la dueña, obtuvo el recurso →
//! costura. La misma pregunta la hace la skill `revisar-seguridad`: «¿este
//! endpoint enseña a un Tercero algo que otro endpoint le niega?».
//!
//! ESTE ARCHIVO es el corazón: el predicado de clasificación, lógica PURA y
//! testeable sin red ni credenciales (directiva 28: se cruza la frontera con
//! pruebas en proceso). El driver HTTP que repite las peticiones con cada
//! identidad y construye los `Observado` a partir de respuestas reales, la
//! integración con recon y la config del juego de identidades por programa son
//! el incremento 2 (necesita cuentas de prueba, que monta Juan).

//! Librería INDEPENDIENTE: el motor no depende de ningún orquestador. Las FASES
//! que persisten hallazgos y aplican el anti-baneo del consumidor viven en el
//! consumidor (p. ej. nexus), no aquí — aquí está el motor puro y su driver.

/// Papel de una identidad frente a un recurso concreto del DUEÑO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Papel {
    /// La identidad dueña del recurso (autorizada). Es la referencia.
    Dueno,
    /// Un par: otra cuenta del mismo nivel. Que vea el recurso del dueño es
    /// privesc HORIZONTAL (IDOR/BOLA).
    Par,
    /// Menor privilegio (p. ej. usuario normal contra función de admin). Que
    /// alcance el recurso es privesc VERTICAL.
    MenorPrivilegio,
    /// Sin autenticar. Que obtenga el recurso protegido es fuga SIN AUTH.
    Anonimo,
}

/// Lo mínimo observado de una respuesta para poder diffear. Lo construye el
/// driver HTTP (incremento 2) o el test (incremento 1).
#[derive(Debug, Clone, Copy)]
pub struct Observado {
    pub papel: Papel,
    pub status: u16,
    pub cuerpo_len: usize,
    /// Hash del cuerpo (normalizado en el incremento 2). "Mismo recurso" de más
    /// confianza = misma firma.
    pub cuerpo_sig: u64,
    /// ¿El cuerpo es una página HTML? Un endpoint de API sirve DATOS (JSON), no
    /// una página; un 2xx `text/html` sobre una ruta de API es casi siempre el
    /// *shell* del SPA servido por el catch-all del frontend, no un bypass. Es la
    /// discriminación que faltaba y dejaba pasar el FP de `app.aikido.dev/api/…`
    /// (verificado 2026-08-21: `/`,`%2e`,`..;/`,X-Original-URL → 200 con el
    /// `index.html` público de 19 KB). Ver `es_bypass`.
    pub es_html: bool,
    /// ¿El cuerpo es un CHALLENGE de WAF/bot (Cloudflare "Just a moment…")? Un
    /// 403/401 así NO es un endpoint protegido —es un desafío anti-bot— y variar
    /// la petición para "saltarlo" no es un bypass de control de acceso (FP medido
    /// en producción 2026-08-21 sobre platform.cloudways.com). Ver `es_bypass`.
    pub es_challenge: bool,
}

/// La costura de acceso detectada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Costura {
    /// Un par obtiene el recurso del dueño (IDOR/BOLA).
    IdorHorizontal,
    /// Una identidad de menor privilegio alcanza el recurso.
    PrivEscVertical,
    /// Sin autenticar se obtiene el recurso protegido.
    FugaSinAuth,
}

impl Costura {
    /// La clase OWASP/ligera de la costura (para que el consumidor la mapee a su
    /// propio catálogo de vulnerabilidades). `idor` = objeto ajeno; `bac` = fuga
    /// sin auth o privesc vertical.
    pub fn clase(self) -> &'static str {
        match self {
            Costura::IdorHorizontal => "idor",
            Costura::PrivEscVertical | Costura::FugaSinAuth => "bac",
        }
    }

    /// Nombre estable del hallazgo (dedup por (url, vuln_name), así que no lleva
    /// la confianza: misma costura en la misma URL es el mismo hallazgo).
    pub fn nombre(self) -> &'static str {
        match self {
            Costura::IdorHorizontal => "control-de-acceso-idor-horizontal",
            Costura::FugaSinAuth => "control-de-acceso-fuga-sin-auth",
            Costura::PrivEscVertical => "control-de-acceso-privesc-vertical",
        }
    }

    /// CWE para el reporte a H1.
    pub fn cwe(self) -> &'static str {
        match self {
            Costura::IdorHorizontal => "CWE-639", // Authorization Bypass Through User-Controlled Key
            Costura::FugaSinAuth => "CWE-862",     // Missing Authorization
            Costura::PrivEscVertical => "CWE-285", // Improper Authorization
        }
    }
}

impl Veredicto {
    /// Severidad: la de la clase si la confianza es Alta; UN ESCALÓN MENOS si es
    /// Media (firma no exacta, solo longitud), para que el revisor manual vea la
    /// incertidumbre en el propio hallazgo en vez de tener que recordarla.
    pub fn severity(self) -> &'static str {
        match (self.costura, self.confianza) {
            (Costura::IdorHorizontal, Confianza::Alta) => "medium",
            (Costura::IdorHorizontal, Confianza::Media) => "low",
            // fuga sin auth / privesc vertical: más graves de base.
            (_, Confianza::Alta) => "high",
            (_, Confianza::Media) => "medium",
        }
    }
}

/// Cuánta confianza da la señal. La firma EXACTA es alta; la mera coincidencia de
/// LONGITUD es media —puede ser el mismo molde con PII distinta (IDOR real) o dos
/// recursos distintos del mismo tamaño (falso positivo)—, así que se marca, no se
/// esconde (directiva 20). El incremento 2 manda las `Media` al verificador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confianza {
    Alta,
    Media,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Veredicto {
    pub costura: Costura,
    pub confianza: Confianza,
}

/// ¿Dos cuerpos 2xx son "el mismo recurso" por longitud? Exige que ambos tengan
/// tamaño no trivial (una página de error genérica de pocos bytes no cuenta) y
/// que la razón menor/mayor supere `umbral`.
fn longitudes_equivalentes(a: usize, b: usize, umbral: f64) -> bool {
    const MIN_LEN: usize = 64; // por debajo de esto es ruido (error page, redirect)
    if a < MIN_LEN || b < MIN_LEN {
        return false;
    }
    let (menor, mayor) = if a <= b { (a, b) } else { (b, a) };
    (menor as f64 / mayor as f64) >= umbral
}

/// El predicado. Dada la respuesta del DUEÑO (autorizado) y la de OTRA identidad
/// sobre la MISMA petición a un recurso del dueño, ¿hay costura de acceso?
///
/// Reglas, en orden (cada una descarta un falso positivo real):
/// 1. El dueño tuvo que ver 2xx: si el propio dueño no accedió, no hay recurso
///    que filtrar (endpoint roto → nada que marcar).
/// 2. El otro tuvo que ver 2xx: un 404/403/401 es el control FUNCIONANDO
///    (la señal de `medico`, invertida).
/// 3. Y el MISMO recurso: firma igual (Alta) o longitud equivalente (Media). Si
///    el otro ve 200 pero con OTRO cuerpo, está viendo LO SUYO, no lo del dueño
///    → no es fuga. Este es el guardia contra el mayor falso positivo (un par
///    pidiendo /api/me recibe su propio perfil, 200, cuerpo distinto).
/// 4. El dueño consigo mismo nunca es costura.
///
/// `umbral` ∈ [0,1]: fracción de longitud para "equivalente" cuando la firma no
/// coincide. 1.0 = exige longitud idéntica; 0.0 = cualquier par de 2xx (no usar).
pub fn clasificar(
    dueno: &Observado,
    otro: &Observado,
    publico: Option<&Observado>,
    umbral: f64,
) -> Option<Veredicto> {
    let es_2xx = |s: u16| (200..300).contains(&s);
    if !es_2xx(dueno.status) || !es_2xx(otro.status) {
        return None;
    }
    // Regla 0 — GUARDIA DE RECURSO PÚBLICO (el falso positivo medido el
    // 2026-08-24: 46 "IDOR" sobre fuentes .ttf/.woff, SVGs y .well-known). Si un
    // cliente ANÓNIMO (sin credenciales) obtiene EL MISMO recurso 2xx —firma de
    // cuerpo IDÉNTICA a la del dueño— entonces no hay control de acceso que saltar:
    // lo ve cualquiera. Se aplica a TODAS las costuras: un recurso público no es ni
    // IDOR, ni privesc, ni fuga (era público de entrada).
    //
    // SOLO por firma EXACTA, NUNCA por longitud (contra el falso negativo de la
    // revisión): la firma idéntica PRUEBA que el anónimo obtuvo el mismo recurso; la
    // longitud parecida solo prueba que obtuvo ALGO del mismo tamaño, y eso no basta
    // para descartar. Descartar por longitud suprimiría en silencio un IDOR REAL
    // (par con firma idéntica al dueño) si el anónimo devuelve una página de
    // login/error 2xx que por azar cae dentro del umbral — el descarte no puede ser
    // más débil que la confirmación (la longitud vale para CONFIRMAR como Media,
    // regla 3; jamás para suprimir). Y un 401/403/404 anónimo es el control
    // FUNCIONANDO: NO descarta nada, ahí sí hay algo que proteger.
    if let Some(pub_obs) = publico {
        if es_2xx(pub_obs.status) && pub_obs.cuerpo_sig == dueno.cuerpo_sig {
            return None;
        }
    }
    let costura = match otro.papel {
        Papel::Dueno => return None,
        Papel::Par => Costura::IdorHorizontal,
        Papel::MenorPrivilegio => Costura::PrivEscVertical,
        Papel::Anonimo => Costura::FugaSinAuth,
    };
    if otro.cuerpo_sig == dueno.cuerpo_sig {
        return Some(Veredicto { costura, confianza: Confianza::Alta });
    }
    if longitudes_equivalentes(dueno.cuerpo_len, otro.cuerpo_len, umbral) {
        return Some(Veredicto { costura, confianza: Confianza::Media });
    }
    None
}

/// Umbral por defecto de longitud-equivalente: conservador (98%).
pub const UMBRAL_DEFECTO: f64 = 0.98;

impl Papel {
    /// Parsea el `papel` de la tabla `identidades`. Devuelve None ante un papel
    /// desconocido para que el llamante falle RUIDOSO (directiva 20): un typo en
    /// la config a mano no debe convertirse en un juego silenciosamente incompleto.
    pub fn desde_str(s: &str) -> Option<Papel> {
        match s {
            "dueno" => Some(Papel::Dueno),
            "par" => Some(Papel::Par),
            "menor" => Some(Papel::MenorPrivilegio),
            "anonimo" => Some(Papel::Anonimo),
            _ => None,
        }
    }
}

/// Una identidad cargada del almacén: su papel y las cabeceras HTTP que la
/// autentican (Cookie / Authorization). El anónimo va sin cabeceras. Lo llena
/// Juan a mano (config manual por programa, decidido el 2026-08-19).
#[derive(Debug, Clone)]
pub struct Identidad {
    pub papel: Papel,
    pub cabeceras: Vec<(String, String)>,
}

/// ¿El juego permite diffear? Hace falta el DUEÑO (la referencia autorizada) y al
/// menos una identidad más contra la que comparar (par/menor/anónimo). Sin eso el
/// motor se salta el programa: no hay nada que comparar, y un juego a medias que
/// "corre" sería peor que uno que no corre (directiva 20).
pub fn juego_listo(ids: &[Identidad]) -> bool {
    let tiene_dueno = ids.iter().any(|i| i.papel == Papel::Dueno);
    let tiene_otro = ids.iter().any(|i| i.papel != Papel::Dueno);
    tiene_dueno && tiene_otro
}

// ---- Incremento 2b: el driver HTTP que cruza la frontera (directiva 28) ----

/// Una petición a repetir con cada identidad. Solo GET por diseño: idempotente,
/// «sin daño» (mandato de Juan). El motor NUNCA manda POST/PUT/DELETE sobre un
/// recurso ajeno — probar una escritura destructiva SÍ causa daño.
#[derive(Debug, Clone)]
pub struct Solicitud {
    pub url: String,
}

/// Cliente HTTP del motor: NO sigue redirecciones (un 302 a /login ES la
/// respuesta de control de acceso; seguirlo la enmascara) y con timeout corto.
pub fn cliente(user_agent: &str) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(user_agent.to_string())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()
}

/// Firma del cuerpo: hash estable de los bytes. CRUDA en este incremento; la
/// normalización que retira lo reflejado del solicitante (CSRF token, su propio
/// nombre) —para no perder un IDOR cuyo cuerpo lleva algo de quien pide— es
/// refinamiento posterior. Mientras tanto ese caso cae al camino de longitud
/// (Confianza::Media), no se pierde.
pub fn firma_cuerpo(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// ¿La respuesta es una página HTML? Mira primero la cabecera `Content-Type` y,
/// como respaldo (servidores que la mienten o la omiten), olfatea el inicio del
/// cuerpo buscando `<!doctype html`/`<html`. Se usa para descartar el *shell*
/// del SPA como falso bypass (ver `es_bypass`). El *sniff* mira solo el prefijo:
/// una respuesta JSON que MENCIONE `<html>` en un valor no cuenta como página.
pub fn cuerpo_es_html(content_type: Option<&str>, cuerpo: &[u8]) -> bool {
    if let Some(ct) = content_type {
        if ct.to_ascii_lowercase().contains("text/html") {
            return true;
        }
    }
    let prefijo = &cuerpo[..cuerpo.len().min(256)];
    let txt = String::from_utf8_lossy(prefijo);
    let txt = txt.trim_start().to_ascii_lowercase();
    txt.starts_with("<!doctype html") || txt.starts_with("<html")
}

/// ¿El cuerpo es un CHALLENGE de WAF/bot (Cloudflare "Just a moment…" y afines)?
/// Un 401/403 con este cuerpo NO es un endpoint protegido —es un desafío anti-bot
/// contra nuestra IP— y variar la petición para "saltarlo" no es un bypass de
/// control de acceso, sino que la variante pasó el desafío y ve la página real
/// (FP medido en producción 2026-08-21 sobre platform.cloudways.com: 403
/// "Just a moment…" → 200 página real, html→html, que `es_html` no distingue).
pub fn cuerpo_es_challenge(cuerpo: &[u8]) -> bool {
    let prefijo = &cuerpo[..cuerpo.len().min(4096)];
    let txt = String::from_utf8_lossy(prefijo).to_ascii_lowercase();
    const MARCAS: &[&str] = &[
        "just a moment",
        "attention required",
        "cf-browser-verification",
        "checking your browser",
        "/cdn-cgi/challenge-platform",
        "enable javascript and cookies to continue",
    ];
    MARCAS.iter().any(|m| txt.contains(m))
}

/// Firma del cuerpo NORMALIZADA: retira los VALORES de credencial de la propia
/// identidad (cookies/tokens de sus cabeceras) que la app pueda REFLEJAR en la
/// respuesta antes de firmar. Sin esto, un IDOR cuyo cuerpo lleva el token de
/// quien pide daría firmas distintas para el MISMO recurso servido a dos
/// identidades → caería a Media en vez de Alta, o se perdería.
///
/// Seguro (bajo FP, directiva 23): retirar una cadena específica de UNA identidad
/// no puede hacer colisionar dos recursos DISTINTOS, salvo que solo se
/// diferenciaran en esa credencial —que es exactamente el caso reflejado que se
/// quiere neutralizar—. Solo se tocan tokens de ≥8 chars (alta entropía); el
/// anónimo (sin cabeceras) se firma crudo.
pub fn firma_normalizada(cuerpo: &[u8], id: &Identidad) -> u64 {
    let mut texto = String::from_utf8_lossy(cuerpo).into_owned();
    for (_, valor) in &id.cabeceras {
        // El valor puede ser "session=ABC123..." o "Bearer XYZ..."; se parte por
        // los separadores típicos y se retira cada trozo "jugoso" (≥8 chars).
        for token in valor
            .split([';', '=', ' ', ',', '"'])
            .map(str::trim)
            .filter(|t| t.len() >= 8)
        {
            texto = texto.replace(token, "<ID>");
        }
    }
    firma_cuerpo(texto.as_bytes())
}

/// Observa una petición GET vista por UNA identidad (idempotente, sin seguir
/// redirecciones). Construye el `Observado` real: status, longitud, firma.
pub async fn observar(
    client: &reqwest::Client,
    sol: &Solicitud,
    id: &Identidad,
) -> reqwest::Result<Observado> {
    let mut req = client.get(&sol.url);
    for (k, v) in &id.cabeceras {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.bytes().await?;
    Ok(Observado {
        papel: id.papel,
        status,
        cuerpo_len: bytes.len(),
        // Normalizada: neutraliza lo reflejado de la propia credencial para que el
        // mismo recurso servido a dos identidades case por firma (Alta), no por
        // longitud (Media).
        cuerpo_sig: firma_normalizada(&bytes, id),
        es_html: cuerpo_es_html(ct.as_deref(), &bytes),
        es_challenge: cuerpo_es_challenge(&bytes),
    })
}

/// Diffea una petición sobre un juego de identidades: observa al DUEÑO (la
/// referencia) y a cada otra identidad, y clasifica cada par. Devuelve las
/// costuras. El anti-baneo (pacing/backoff entre ENDPOINTS) lo aplica el llamante
/// con el `Guard`; aquí solo se hacen las 2-3 peticiones al MISMO endpoint (una
/// ráfaga pequeña y realista, como cargar una página).
/// Devuelve `(costuras, vio_senal_de_baneo)`. La segunda es para que el llamante
/// APLIQUE el backoff/cortacircuitos: un 429/503 en cualquiera de las peticiones
/// significa que el objetivo nos frena, y en un VPS compartido eso manda parar.
pub async fn diffear(
    client: &reqwest::Client,
    sol: &Solicitud,
    ids: &[Identidad],
    umbral: f64,
) -> reqwest::Result<(Vec<Veredicto>, bool)> {
    let dueno_id = match ids.iter().find(|i| i.papel == Papel::Dueno) {
        Some(d) => d,
        None => return Ok((vec![], false)), // sin dueño no hay referencia
    };
    let dueno_obs = observar(client, sol, dueno_id).await?;
    let mut baneo = es_senal_de_baneo(dueno_obs.status);
    // LÍNEA BASE ANÓNIMA: la MISMA petición SIN credenciales. Es el discriminante
    // que separa el IDOR real del recurso público. Se hace SIEMPRE; si el anónimo
    // obtiene el recurso, `clasificar` descarta la costura (regla 0).
    let anon = Identidad { papel: Papel::Anonimo, cabeceras: vec![] };
    let publico_obs = observar(client, sol, &anon).await?;
    if es_senal_de_baneo(publico_obs.status) {
        baneo = true;
    }
    let mut out = Vec::new();
    for otro in ids.iter().filter(|i| i.papel != Papel::Dueno) {
        let obs = observar(client, sol, otro).await?;
        if es_senal_de_baneo(obs.status) {
            baneo = true;
        }
        if let Some(v) = clasificar(&dueno_obs, &obs, Some(&publico_obs), umbral) {
            out.push(v);
        }
    }
    Ok((out, baneo))
}

// ---- Evasión de control de acceso (bypass de 403/401), SIN login ----
//
// A un endpoint PROTEGIDO (401/403 sin auth) se le prueban trucos conocidos de
// evasión; si alguno devuelve 2xx con contenido real (distinto de la página de
// error), se saltó el control. No necesita NINGUNA cuenta — es la vía para
// atacar sin login. Todas las técnicas son GET/POST idempotentes (sin daño).

/// Una técnica de evasión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tecnica {
    /// Cabecera de valor fijo (engaña ACLs por IP o proxies de reescritura).
    Cabecera(&'static str, &'static str),
    /// Cabecera cuyo valor es la RUTA de la URL (X-Original-URL / X-Rewrite-URL).
    CabeceraRuta(&'static str),
    /// Sufijo a la ruta (trailing slash, `%2e`, `..;/`…): confunde al normalizador.
    Sufijo(&'static str),
    /// Cambia el verbo HTTP (un GET bloqueado puede permitir POST).
    Verbo(&'static str),
}

/// El repertorio de evasión. Conocidas y no destructivas.
pub const TECNICAS_EVASION: &[Tecnica] = &[
    // Cabeceras de IP de confianza (proxies/ACLs que confían en el cliente).
    Tecnica::Cabecera("X-Forwarded-For", "127.0.0.1"),
    Tecnica::Cabecera("X-Custom-IP-Authorization", "127.0.0.1"),
    Tecnica::Cabecera("X-Originating-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Remote-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Client-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Real-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Forwarded-Host", "localhost"),
    // Ampliación 2026-08-21: cabeceras de confianza que usan proxies reales
    // (Cloudflare, clusters, HAProxy). Moderado a propósito —cada técnica es una
    // petición más sobre la IP compartida (memoria muro-403); la fase corta al
    // primer bypass y para ante el muro, así que el coste real es acotado—.
    Tecnica::Cabecera("True-Client-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-Cluster-Client-IP", "127.0.0.1"),
    Tecnica::Cabecera("CF-Connecting-IP", "127.0.0.1"),
    Tecnica::Cabecera("X-ProxyUser-Ip", "127.0.0.1"),
    Tecnica::Cabecera("X-Forwarded-Scheme", "http"),
    // Reescritura de ruta por cabecera (proxies que enrutan por X-*-URL).
    Tecnica::CabeceraRuta("X-Original-URL"),
    Tecnica::CabeceraRuta("X-Rewrite-URL"),
    Tecnica::CabeceraRuta("X-Override-URL"),
    // Sufijos que confunden al normalizador de ruta (todos GET idempotentes).
    Tecnica::Sufijo("/"),
    Tecnica::Sufijo("/."),
    Tecnica::Sufijo("%2e"),
    Tecnica::Sufijo("/..;/"),
    Tecnica::Sufijo("//"),
    Tecnica::Sufijo("/%2e/"),
    Tecnica::Sufijo("?"),
    // Cambio de verbo (un GET bloqueado puede permitir POST). Sin verbos
    // destructivos (PUT/DELETE): el mandato es «sin daño».
    Tecnica::Verbo("POST"),
];

/// Longitud mínima de un cuerpo 2xx para considerarlo "contenido real" y no una
/// página de error/redirect que casualmente dio 2xx.
const MIN_BYPASS: usize = 64;

/// ¿Este status HTTP es una señal de que el objetivo nos está frenando/bloqueando?
/// 429 (Too Many Requests) y 503 (Service Unavailable / WAF) son el «para» explícito.
/// NO se incluye 403: en el control de acceso un 403 es la respuesta ESPERADA de
/// un endpoint protegido, no un baneo. El consumidor la usa para aplicar backoff
/// y su cortacircuitos.
pub fn es_senal_de_baneo(status: u16) -> bool {
    status == 429 || status == 503
}

/// El PREDICADO de evasión (puro, testeable). Dado el baseline (petición plana
/// sin auth) y la respuesta de una técnica, ¿se saltó el control?
///
/// Reglas: el baseline tiene que estar PROTEGIDO (401/403) —si ya daba 2xx el
/// endpoint es público, no hay control que saltar—; la variante tiene que dar
/// 2xx con cuerpo SUSTANTIVO y DISTINTO del baseline (si devuelve la misma página
/// de error, no es un bypass); y —añadido 2026-08-21— la variante NO puede ser
/// una página HTML cuando el baseline no lo era. Un endpoint que responde JSON al
/// bloquear (401/403 de API) y de pronto devuelve `text/html` no ha "abierto sus
/// datos": está sirviendo el *shell* del SPA por el catch-all del frontend cuando
/// la ruta manipulada (sufijo, X-Rewrite-URL) deja de casar con `/api/…`. Eso NO
/// es privilegio ganado. La regla mira el CAMBIO de tipo (no-HTML→HTML) para no
/// crear el falso negativo simétrico: si el propio recurso protegido ES una
/// página HTML (baseline ya HTML), un bypass a otra página HTML sí cuenta.
pub fn es_bypass(baseline: &Observado, variante: &Observado) -> bool {
    matches!(baseline.status, 401 | 403)
        && !baseline.es_challenge
        && (200..300).contains(&variante.status)
        && variante.cuerpo_len >= MIN_BYPASS
        && variante.cuerpo_sig != baseline.cuerpo_sig
        && !(variante.es_html && !baseline.es_html)
}

/// Ejecuta UNA técnica de evasión sobre `url` y devuelve el Observado (papel
/// Anonimo: la evasión es sin auth).
pub async fn observar_evasion(
    client: &reqwest::Client,
    url: &str,
    tecnica: Tecnica,
) -> reqwest::Result<Observado> {
    let mut req = match tecnica {
        Tecnica::Verbo(m) => {
            let metodo = reqwest::Method::from_bytes(m.as_bytes()).unwrap_or(reqwest::Method::GET);
            client.request(metodo, url)
        }
        Tecnica::Sufijo(s) => client.get(format!("{url}{s}")),
        _ => client.get(url),
    };
    req = match tecnica {
        Tecnica::Cabecera(k, v) => req.header(k, v),
        Tecnica::CabeceraRuta(k) => {
            let ruta = reqwest::Url::parse(url)
                .map(|u| u.path().to_string())
                .unwrap_or_else(|_| "/".to_string());
            req.header(k, ruta)
        }
        _ => req,
    };
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.bytes().await?;
    Ok(Observado {
        papel: Papel::Anonimo,
        status,
        cuerpo_len: bytes.len(),
        cuerpo_sig: firma_cuerpo(&bytes),
        es_html: cuerpo_es_html(ct.as_deref(), &bytes),
        es_challenge: cuerpo_es_challenge(&bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(papel: Papel, status: u16, len: usize, sig: u64) -> Observado {
        Observado { papel, status, cuerpo_len: len, cuerpo_sig: sig, es_html: false, es_challenge: false }
    }
    /// Igual que `obs` pero marca el cuerpo como página HTML (shell del SPA).
    fn obs_html(papel: Papel, status: u16, len: usize, sig: u64) -> Observado {
        Observado { papel, status, cuerpo_len: len, cuerpo_sig: sig, es_html: true, es_challenge: false }
    }
    /// Igual que `obs` pero marca el baseline como CHALLENGE de WAF/bot.
    fn obs_challenge(papel: Papel, status: u16, len: usize, sig: u64) -> Observado {
        Observado { papel, status, cuerpo_len: len, cuerpo_sig: sig, es_html: true, es_challenge: true }
    }

    // Ninguna de estas pruebas del PREDICADO pasa `publico` (None): aíslan las
    // reglas 1-4. El guardia de recurso público (regla 0) tiene su propia pareja
    // más abajo.

    // --- RED cases: TIENEN que disparar ---

    #[test]
    fn idor_horizontal_por_firma_exacta_es_alta() {
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 500, 0xABCD); // mismo cuerpo
        let v = clasificar(&dueno, &par, None, UMBRAL_DEFECTO).expect("debe marcar IDOR");
        assert_eq!(v.costura, Costura::IdorHorizontal);
        assert_eq!(v.confianza, Confianza::Alta);
        assert_eq!(v.costura.clase(), "idor");
    }

    #[test]
    fn fuga_sin_auth_se_detecta() {
        // Predicado sin línea base: FugaSinAuth se detecta. En el camino real
        // `diffear` pasa la línea base anónima, que para un recurso público la
        // descarta (regla 0) — ver `recurso_publico_no_marca_ninguna_costura`.
        let dueno = obs(Papel::Dueno, 200, 800, 0x11);
        let anon = obs(Papel::Anonimo, 200, 800, 0x11);
        let v = clasificar(&dueno, &anon, None, UMBRAL_DEFECTO).unwrap();
        assert_eq!(v.costura, Costura::FugaSinAuth);
        assert_eq!(v.costura.clase(), "bac");
    }

    #[test]
    fn privesc_vertical_se_detecta() {
        let dueno = obs(Papel::Dueno, 200, 800, 0x22);
        let low = obs(Papel::MenorPrivilegio, 200, 800, 0x22);
        assert_eq!(clasificar(&dueno, &low, None, UMBRAL_DEFECTO).unwrap().costura, Costura::PrivEscVertical);
    }

    #[test]
    fn longitud_equivalente_sin_firma_es_media() {
        // Mismo molde, PII distinta → firmas distintas pero longitud casi igual.
        let dueno = obs(Papel::Dueno, 200, 1000, 0xAAAA);
        let par = obs(Papel::Par, 200, 990, 0xBBBB); // 99% del tamaño
        let v = clasificar(&dueno, &par, None, UMBRAL_DEFECTO).expect("longitud equivalente marca");
        assert_eq!(v.confianza, Confianza::Media, "sin firma exacta, confianza media");
    }

    // --- Regla 0 (recurso PÚBLICO): la pareja del FP medido el 2026-08-24 ---

    #[test]
    fn recurso_publico_no_marca_ninguna_costura() {
        // EL falso positivo medido: 46 "IDOR" sobre fuentes/SVG/.well-known. El
        // par ve el MISMO cuerpo que el dueño, PERO un anónimo también lo obtiene
        // (2xx, mismo cuerpo) → recurso público → NO es costura.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 500, 0xABCD);
        let anon = obs(Papel::Anonimo, 200, 500, 0xABCD); // ¡el anónimo también!
        assert!(
            clasificar(&dueno, &par, Some(&anon), UMBRAL_DEFECTO).is_none(),
            "un recurso que el anónimo obtiene es PÚBLICO, no IDOR"
        );
    }

    #[test]
    fn idor_real_con_anonimo_denegado_si_marca() {
        // El caso ROJO que la regla 0 NO debe tumbar: par ve el recurso del dueño
        // y el anónimo está DENEGADO (401) → IDOR real, Alta.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 500, 0xABCD);
        let anon = obs(Papel::Anonimo, 401, 0, 0x0); // control activo
        let v = clasificar(&dueno, &par, Some(&anon), UMBRAL_DEFECTO)
            .expect("anónimo denegado → el IDOR real sí marca");
        assert_eq!(v.costura, Costura::IdorHorizontal);
        assert_eq!(v.confianza, Confianza::Alta);
    }

    #[test]
    fn anonimo_de_tamano_parecido_no_tumba_un_idor_real() {
        // Falso negativo cazado por la revisión (2026-08-24): un IDOR REAL (par con
        // firma idéntica al dueño) NO se descarta porque el anónimo 2xx caiga por
        // azar dentro del 98% de longitud con OTRO cuerpo. El descarte de la regla 0
        // es SOLO por firma exacta; la longitud parecida jamás suprime.
        let dueno = obs(Papel::Dueno, 200, 1000, 0xAAAA);
        let par = obs(Papel::Par, 200, 1000, 0xAAAA); // IDOR real, firma idéntica al dueño
        let anon = obs(Papel::Anonimo, 200, 990, 0xDDDD); // ~99% de longitud, cuerpo DISTINTO
        let v = clasificar(&dueno, &par, Some(&anon), UMBRAL_DEFECTO)
            .expect("un anónimo de tamaño parecido pero cuerpo distinto NO suprime el IDOR real");
        assert_eq!(v.costura, Costura::IdorHorizontal);
        assert_eq!(v.confianza, Confianza::Alta);
    }

    // --- GREEN cases: NO deben disparar (cada uno mata un falso positivo) ---

    #[test]
    fn recurso_ajeno_cerrado_con_404_no_marca() {
        // LA señal de medico: el control correcto devuelve 404, no 403.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 404, 20, 0x0);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn recurso_ajeno_cerrado_con_403_no_marca() {
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 403, 30, 0x0);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn par_ve_su_propio_dato_no_es_idor() {
        // EL falso positivo grande: /api/me → cada uno ve LO SUYO. 200 los dos,
        // pero cuerpos distintos y tamaños distintos → NO es fuga.
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let par = obs(Papel::Par, 200, 640, 0x1234); // su propio perfil, más grande
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn dueno_sin_acceso_no_hay_fuga() {
        // Si el propio dueño no vio el recurso (endpoint roto), no hay nada que
        // filtrar aunque el otro dé 200.
        let dueno = obs(Papel::Dueno, 404, 20, 0x0);
        let par = obs(Papel::Par, 200, 500, 0xABCD);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn dueno_consigo_mismo_no_es_costura() {
        let dueno = obs(Papel::Dueno, 200, 500, 0xABCD);
        let dueno2 = obs(Papel::Dueno, 200, 500, 0xABCD);
        assert!(clasificar(&dueno, &dueno2, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn cuerpo_corto_no_dispara_por_longitud() {
        // Dos páginas de error de 20 bytes con 200: por debajo de MIN_LEN no
        // cuentan como "mismo recurso" aunque la longitud coincida.
        let dueno = obs(Papel::Dueno, 200, 20, 0xAAAA);
        let par = obs(Papel::Par, 200, 20, 0xBBBB);
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn longitudes_muy_distintas_no_marcan() {
        let dueno = obs(Papel::Dueno, 200, 1000, 0xAAAA);
        let par = obs(Papel::Par, 200, 300, 0xBBBB); // 30% → por debajo de 0.98
        assert!(clasificar(&dueno, &par, None, UMBRAL_DEFECTO).is_none());
    }

    #[test]
    fn papel_desde_str_conocidos_y_typo() {
        assert_eq!(Papel::desde_str("dueno"), Some(Papel::Dueno));
        assert_eq!(Papel::desde_str("par"), Some(Papel::Par));
        assert_eq!(Papel::desde_str("menor"), Some(Papel::MenorPrivilegio));
        assert_eq!(Papel::desde_str("anonimo"), Some(Papel::Anonimo));
        assert_eq!(Papel::desde_str("Dueno"), None, "case-sensitive: un typo es None, no un default");
        assert_eq!(Papel::desde_str("admin"), None);
    }

    fn ident(papel: Papel) -> Identidad {
        Identidad { papel, cabeceras: vec![] }
    }

    #[test]
    fn juego_listo_exige_dueno_y_otro() {
        assert!(!juego_listo(&[]), "vacío no");
        assert!(!juego_listo(&[ident(Papel::Dueno)]), "solo dueño no");
        assert!(!juego_listo(&[ident(Papel::Par)]), "solo par (sin dueño) no");
        assert!(juego_listo(&[ident(Papel::Dueno), ident(Papel::Par)]), "dueño+par sí");
        assert!(juego_listo(&[ident(Papel::Dueno), ident(Papel::Anonimo)]), "dueño+anónimo sí (fuga sin auth)");
    }

    #[test]
    fn severidad_refleja_la_confianza() {
        let v = |c, conf| Veredicto { costura: c, confianza: conf };
        assert_eq!(v(Costura::IdorHorizontal, Confianza::Alta).severity(), "medium");
        assert_eq!(v(Costura::IdorHorizontal, Confianza::Media).severity(), "low", "Media baja un escalón");
        assert_eq!(v(Costura::FugaSinAuth, Confianza::Alta).severity(), "high");
        assert_eq!(v(Costura::FugaSinAuth, Confianza::Media).severity(), "medium");
        assert_eq!(v(Costura::PrivEscVertical, Confianza::Alta).severity(), "high");
    }

    #[test]
    fn nombre_y_cwe_estables_por_clase() {
        assert_eq!(Costura::IdorHorizontal.cwe(), "CWE-639");
        assert_eq!(Costura::FugaSinAuth.cwe(), "CWE-862");
        assert_eq!(Costura::IdorHorizontal.nombre(), "control-de-acceso-idor-horizontal");
    }

    fn id_con(cookie: &str) -> Identidad {
        Identidad { papel: Papel::Dueno, cabeceras: vec![("Cookie".into(), cookie.into())] }
    }

    #[test]
    fn firma_normalizada_neutraliza_la_credencial_reflejada() {
        // El MISMO recurso servido a dos identidades, pero cada cuerpo refleja el
        // token de quien pide. Crudo darían firmas distintas; normalizado, iguales.
        let dueno = id_con("session=ALICE_TOKEN_1234");
        let par = id_con("session=BOB_TOKEN_5678");
        let cuerpo_dueno = b"SECRETO-DEL-PEDIDO-42 (tu token: ALICE_TOKEN_1234)";
        let cuerpo_par = b"SECRETO-DEL-PEDIDO-42 (tu token: BOB_TOKEN_5678)";

        assert_ne!(
            firma_cuerpo(cuerpo_dueno), firma_cuerpo(cuerpo_par),
            "crudo: distintos por el token reflejado"
        );
        assert_eq!(
            firma_normalizada(cuerpo_dueno, &dueno),
            firma_normalizada(cuerpo_par, &par),
            "normalizado: el mismo recurso casa pese a la credencial reflejada"
        );
    }

    #[test]
    fn firma_normalizada_no_colisiona_recursos_distintos() {
        // Dos recursos GENUINAMENTE distintos no deben colisionar por normalizar.
        let dueno = id_con("session=ALICE_TOKEN_1234");
        let par = id_con("session=BOB_TOKEN_5678");
        let pedido = b"SECRETO-DEL-PEDIDO-42 (tu token: ALICE_TOKEN_1234)";
        let factura = b"FACTURA-DISTINTA-99-otros-campos (tu token: BOB_TOKEN_5678)";
        assert_ne!(
            firma_normalizada(pedido, &dueno),
            firma_normalizada(factura, &par),
            "recursos distintos siguen con firmas distintas"
        );
    }

    #[test]
    fn firma_normalizada_del_anonimo_es_la_cruda() {
        let anon = Identidad { papel: Papel::Anonimo, cabeceras: vec![] };
        let cuerpo = b"contenido cualquiera sin credencial";
        assert_eq!(firma_normalizada(cuerpo, &anon), firma_cuerpo(cuerpo));
    }

    // --- Evasión de control de acceso (bypass 403/401) ---

    #[test]
    fn bypass_403_a_200_con_contenido_es_bypass() {
        let base = obs(Papel::Anonimo, 403, 30, 0xE1); // protegido
        let variante = obs(Papel::Anonimo, 200, 800, 0xAA); // contenido real, distinto
        assert!(es_bypass(&base, &variante));
    }

    #[test]
    fn bypass_401_tambien_cuenta() {
        let base = obs(Papel::Anonimo, 401, 20, 0xE2);
        let variante = obs(Papel::Anonimo, 200, 500, 0xBB);
        assert!(es_bypass(&base, &variante));
    }

    #[test]
    fn endpoint_publico_no_es_bypass() {
        // baseline ya daba 2xx → no hay control que saltar.
        let base = obs(Papel::Anonimo, 200, 500, 0xCC);
        let variante = obs(Papel::Anonimo, 200, 500, 0xCC);
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn variante_sigue_bloqueada_no_es_bypass() {
        let base = obs(Papel::Anonimo, 403, 30, 0xE1);
        let variante = obs(Papel::Anonimo, 403, 30, 0xE1);
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn misma_pagina_de_error_con_200_no_es_bypass() {
        // Algunos sitios devuelven 200 con "acceso denegado": mismo cuerpo que el
        // baseline → no es un bypass real.
        let base = obs(Papel::Anonimo, 403, 200, 0xDEAD);
        let variante = obs(Papel::Anonimo, 200, 200, 0xDEAD); // misma firma
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn cuerpo_corto_no_es_bypass() {
        let base = obs(Papel::Anonimo, 403, 30, 0xE1);
        let variante = obs(Papel::Anonimo, 200, 10, 0xAA); // por debajo de MIN_BYPASS
        assert!(!es_bypass(&base, &variante));
    }

    #[test]
    fn baseline_404_no_dispara_evasion() {
        let base = obs(Papel::Anonimo, 404, 20, 0xE1);
        let variante = obs(Papel::Anonimo, 200, 500, 0xAA);
        assert!(!es_bypass(&base, &variante), "solo 401/403 son candidatos");
    }

    // ---- FP del shell del SPA (verificado en app.aikido.dev, 2026-08-21) ----
    #[test]
    fn shell_html_del_spa_no_es_bypass() {
        let base = obs(Papel::Anonimo, 401, 66, 0x401A); // {"...":"No auth"} JSON
        let variante = obs_html(Papel::Anonimo, 200, 19329, 0x5A0F); // index.html
        assert!(
            !es_bypass(&base, &variante),
            "un 2xx text/html sobre baseline no-HTML es el shell del SPA, no un bypass"
        );
    }

    #[test]
    fn bypass_a_datos_json_sigue_contando() {
        let base = obs(Papel::Anonimo, 401, 66, 0x401A);
        let variante = obs(Papel::Anonimo, 200, 300, 0xDA7A); // datos, no-HTML
        assert!(es_bypass(&base, &variante));
    }

    #[test]
    fn bypass_de_pagina_html_protegida_sigue_contando() {
        let base = obs_html(Papel::Anonimo, 403, 200, 0xE770); // página de error HTML
        let variante = obs_html(Papel::Anonimo, 200, 800, 0xAD31); // panel HTML abierto
        assert!(es_bypass(&base, &variante));
    }

    // FP medido 2026-08-21 (platform.cloudways.com): el baseline 403 es un
    // CHALLENGE de Cloudflare ("Just a moment…"), no un endpoint protegido, y la
    // variante que lo "salta" es la página real (html→html, que `es_html` no
    // distingue). Mutante = quitar `!baseline.es_challenge` → este test se pone
    // rojo (sin la cláusula, 403→200 con html→html y firma distinta pasaría).
    #[test]
    fn challenge_de_waf_como_baseline_no_es_bypass() {
        let base = obs_challenge(Papel::Anonimo, 403, 5413, 0xC0FF); // "Just a moment…"
        let variante = obs_html(Papel::Anonimo, 200, 88076, 0xFEED); // página real
        assert!(!es_bypass(&base, &variante));
    }

    // Pareja discriminante: un 403 GENUINO (no challenge) a otra página HTML sigue
    // contando — la cláusula solo mata el challenge, no el bypass html→html real.
    #[test]
    fn cuerpo_es_challenge_detecta_y_no_falsea() {
        assert!(cuerpo_es_challenge(b"<!DOCTYPE html><title>Just a moment...</title>"));
        assert!(cuerpo_es_challenge(b"<html>Attention Required! | Cloudflare</html>"));
        // Una página HTML benigna NO es un challenge.
        assert!(!cuerpo_es_challenge(b"<!DOCTYPE html><html><body>Panel de admin</body></html>"));
        assert!(!cuerpo_es_challenge(b"{\"error\":\"forbidden\"}"));
    }

    #[test]
    fn cuerpo_es_html_por_content_type_y_por_sniff() {
        assert!(cuerpo_es_html(Some("text/html; charset=utf-8"), b"x"));
        assert!(cuerpo_es_html(None, b"  <!DOCTYPE html>\n<html>"));
        assert!(cuerpo_es_html(Some("application/octet-stream"), b"<html><body>"));
        assert!(!cuerpo_es_html(Some("application/json"), b"{\"x\":\"<html>\"}"));
        assert!(!cuerpo_es_html(None, b"{\"status_code\":401}"));
    }
}
