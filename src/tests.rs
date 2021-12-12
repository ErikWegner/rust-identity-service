use std::sync::Arc;

use crate::{build_rocket_instance, HealthMap};

use super::rocket;
use rocket::http::Status;
use rocket::local::blocking::Client;
use rocket::{Build, Rocket};

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
