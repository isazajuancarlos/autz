// SPDX-License-Identifier: MIT
//! Prueba de integración del driver HTTP contra un servidor REAL (directiva 28):
//! IDOR por diffing entre identidades, y evasión de 403. Es lo que valida que el
//! motor cruza la frontera, no solo la lógica pura de las pruebas unitarias.

use autz::{cliente, diffear, es_bypass, observar, observar_evasion, Confianza, Costura, Identidad, Papel, Solicitud, Tecnica, UMBRAL_DEFECTO};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

const CUERPO: &str = "SECRETO-DEL-DUENO-0123456789abcdef0123456789abcdef0123456789abcdef-fin";

async fn vulnerable(h: HeaderMap) -> Response {
    // IDOR HORIZONTAL real: exige estar AUTENTICADO (cualquier cookie), pero NO
    // comprueba PROPIEDAD → alice y bob reciben el dato de alice. El anónimo (sin
    // cookie) es DENEGADO: hay control que saltar (si no, sería recurso público).
    let ck = h.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    if ck.contains("s=") {
        (StatusCode::OK, CUERPO).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "").into_response()
    }
}
async fn seguro(h: HeaderMap) -> Response {
    let ck = h.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    if ck.contains("ALICE") {
        (StatusCode::OK, CUERPO).into_response()
    } else {
        (StatusCode::NOT_FOUND, "").into_response() // 404 al ajeno: control correcto
    }
}
async fn bypass(h: HeaderMap) -> Response {
    // 403 plano; 200 con X-Forwarded-For (ACL por IP mal hecha).
    if h.contains_key("x-forwarded-for") {
        (StatusCode::OK, CUERPO).into_response()
    } else {
        (StatusCode::FORBIDDEN, "denegado").into_response()
    }
}

async fn arranca() -> String {
    let app = axum::Router::new()
        .route("/vulnerable", get(vulnerable))
        .route("/seguro", get(seguro))
        .route("/bypass", get(bypass));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn diffing_detecta_idor_y_respeta_lo_seguro() {
    let base = arranca().await;
    let client = cliente("autz-test").unwrap();
    let ids = vec![
        Identidad { papel: Papel::Dueno, cabeceras: vec![("Cookie".into(), "s=ALICE".into())] },
        Identidad { papel: Papel::Par, cabeceras: vec![("Cookie".into(), "s=BOB".into())] },
    ];

    let (v, baneo) = diffear(&client, &Solicitud { url: format!("{base}/vulnerable") }, &ids, UMBRAL_DEFECTO).await.unwrap();
    assert!(!baneo);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].costura, Costura::IdorHorizontal);
    assert_eq!(v[0].confianza, Confianza::Alta);

    let (v2, _) = diffear(&client, &Solicitud { url: format!("{base}/seguro") }, &ids, UMBRAL_DEFECTO).await.unwrap();
    assert!(v2.is_empty(), "un 404 al ajeno no es fuga");
}

#[tokio::test]
async fn evasion_403_detecta_el_bypass() {
    let base = arranca().await;
    let client = cliente("autz-test").unwrap();
    let anon = Identidad { papel: Papel::Anonimo, cabeceras: vec![] };
    let url = format!("{base}/bypass");

    let baseline = observar(&client, &Solicitud { url: url.clone() }, &anon).await.unwrap();
    assert_eq!(baseline.status, 403, "protegido en plano");

    let variante = observar_evasion(&client, &url, Tecnica::Cabecera("X-Forwarded-For", "127.0.0.1")).await.unwrap();
    assert_eq!(variante.status, 200);
    assert!(es_bypass(&baseline, &variante), "X-Forwarded-For salta el 403");
}
