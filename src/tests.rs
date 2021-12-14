use std::sync::Arc;

use crate::oidcclient::{get_client_token, OidcClientState};
use crate::{build_rocket_instance, HealthMap};

use super::rocket;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rocket::http::Status;
use rocket::local::blocking::Client;
use rocket::{Build, Rocket};
use tokio_test::assert_ok;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct TestEnv {
    rocket: Rocket<Build>,
    health_map: Arc<HealthMap>,
}

fn build_rocket_test_instance() -> TestEnv {
    let health_map = Arc::new(HealthMap::new());
    TestEnv {
        rocket: build_rocket_instance(health_map.clone()),
        health_map,
    }
}

#[test]
fn up() {
    let t = build_rocket_test_instance();
    let client = Client::tracked(t.rocket).expect("valid rocket instance");
    let response = client.get("/up").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some("OK".into()));
}

#[test]
fn health_simple_ok() {
    let t = build_rocket_test_instance();
    t.health_map.clear();
    t.health_map.insert("con".to_string(), "OK".to_string());
    let client = Client::tracked(t.rocket).expect("valid rocket instance");
    let response = client.get("/health").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some("OK".into()));
}

#[test]
fn health_simple_fail() {
    let t = build_rocket_test_instance();
    t.health_map.clear();
    t.health_map
        .insert("con".to_string(), "failed to connect".to_string());
    let client = Client::tracked(t.rocket).expect("valid rocket instance");
    let response = client.get("/health").dispatch();
    assert_eq!(response.status(), Status::BadGateway);
    assert_eq!(
        response.into_string(),
        Some("{\"faults\":{\"con\":\"failed to connect\"}}".into())
    );
}

#[test]
fn retrieve_token_returns_token() {
    // Arrange
    // Start a background HTTP server on a random local port
    let mock_server = tokio_test::block_on(MockServer::start());
    let token_endpoint_path: String = format!(
        "/provider/path-{}",
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(|c| c as char)
            .collect::<String>()
    );
    let token: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(|c| c as char)
        .collect();
    let oidc_client_state = Arc::new(OidcClientState::init());
    tokio_test::block_on(
        Mock::given(method("POST"))
            .and(path(&token_endpoint_path))
            .respond_with(ResponseTemplate::new(200).set_body_string(&token))
            .mount(&mock_server),
    );
    let token_endpoint = format!("{}{}", mock_server.uri(), token_endpoint_path);

    // Act
    let r = tokio_test::block_on(get_client_token(&oidc_client_state, token_endpoint));

    // Assert
    assert_ok!(&r);
    let tokenresult = r.unwrap();
    assert_eq!(tokenresult, token);
}
