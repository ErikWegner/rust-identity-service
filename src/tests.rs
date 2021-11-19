use crate::build_rocket_instance;
use crate::redismock::get_redis_mock;
use ridser::cfg::RuntimeConfiguration;
use rocket::local::blocking::Client;

use super::rocket;
use rocket::http::{ContentType, Status};

#[test]
fn login_returns_url() {
    // Arrage
    let rc = RuntimeConfiguration {
        authorization_endpoint: "https://my.real.auth/auth/login".to_string(),
        client_id: "b4b3fbf2-f65e-40b5-b449-4b9825382140".to_string(),
        redirect_uri: "https://front.end.server/auth/callback".to_string(),
        token_url: "https://my.real.auth/auth/token".to_string(),
    };
    let conn = get_redis_mock();

    let rocket = build_rocket_instance(rc, Box::new(conn));
    let client = Client::tracked(rocket).expect("valid rocket instance");

    // Act
    let response = client.get("/login?state=a6jj3&client_id=be734165-952d-4e68-98fb-fe1dabf93349").dispatch();

    // Assert
    assert_eq!(response.status(), Status::SeeOther);
    assert!(response.headers().contains("Location"));
    assert_eq!(response.headers().get_one("Location"), Some("https://my.real.auth/auth/login?response_type=code&client_id=be734165-952d-4e68-98fb-fe1dabf93349&redirect_uri=https%3A%2F%2Ffront.end.server%2Fauth%2Fcallback&scope=openid&state=a6jj3"));
}

#[test]
fn login_without_clientid_returns_bad_request() {
    // Arrage
    let rc = RuntimeConfiguration {
        authorization_endpoint: "https://my.real.auth/auth/login".to_string(),
        client_id: "b4b3fbf2-f65e-40b5-b449-4b9825382140".to_string(),
        redirect_uri: "https://front.end.server/auth/callback".to_string(),
        token_url: "https://my.real.auth/auth/token".to_string(),
    };
    let conn = get_redis_mock();

    let rocket = build_rocket_instance(rc, Box::new(conn));
    let client = Client::tracked(rocket).expect("valid rocket instance");

    // Act
    let response = client.get("/login?state=a6jj3").dispatch();

    // Assert
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(response.into_string().unwrap(), "{\"message\": \"client_id is missing\"}");
}