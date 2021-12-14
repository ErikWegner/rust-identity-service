use std::sync::Arc;

use crate::oidcclient::{get_client_token, ClientCredentials, OidcClientState};
use crate::{build_rocket_instance, HealthMap, LoginConfiguration};

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
    login_configuration: LoginConfiguration,
}

fn random_string(length: usize, prefix: Option<String>) -> String {
    let rs = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(|c| c as char)
        .collect::<String>();
    format!("{}{}", prefix.unwrap_or_default(), rs)
}
fn build_rocket_test_instance() -> TestEnv {
    let health_map = Arc::new(HealthMap::new());
    let login_configuration = LoginConfiguration {
        authorization_endpoint: format!(
            "{}/auth/login",
            random_string(64, Some(String::from("http://unit-test-url/")))
        ),
    };
    TestEnv {
        rocket: build_rocket_instance(health_map.clone(), login_configuration.clone()),
        health_map,
        login_configuration,
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
    let client_credentials = ClientCredentials {
        client_id: "MockClient".to_string(),
        client_secret: "Mock Secret 123".to_string(),
        token_url: format!("{}{}", mock_server.uri(), token_endpoint_path),
    };
    let oidc_client_state = Arc::new(OidcClientState::init(client_credentials));
    tokio_test::block_on(
        Mock::given(method("POST"))
            .and(path(&token_endpoint_path))
            .respond_with(ResponseTemplate::new(200).set_body_string(&token))
            .mount(&mock_server),
    );

    // Act
    let r = tokio_test::block_on(get_client_token(&oidc_client_state));

    // Assert
    assert_ok!(&r);
    let tokenresult = r.unwrap();
    assert_eq!(tokenresult, token);
}

mod login {
    use rocket::{http::Status, local::blocking::Client};

    use crate::tests::{build_rocket_test_instance, random_string};

    #[test]
    fn login_returns_redirect() {
        // Arrange
        let t = build_rocket_test_instance();
        let client = Client::tracked(t.rocket).expect("valid rocket instance");
        let state = random_string(8, None);
        let client_id = random_string(32, None);
        let redirect_uri = String::from("https://front.end.server/auth/callback");
        let expected_location = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}",
            t.login_configuration.authorization_endpoint,
            client_id,
            "https%3A%2F%2Ffront.end.server%2Fauth%2Fcallback",
            state
        );

        // Act
        let response = client
            .get(format!(
                "/login?state={}&client_id={}&redirect_uri={}",
                state, client_id, redirect_uri
            ))
            .dispatch();

        // Assert
        assert_eq!(
            response.status(),
            Status::SeeOther,
            "{}",
            response.into_string().unwrap()
        );
        assert!(response.headers().contains("Location"));
        assert_eq!(
            response.headers().get_one("Location"),
            Some(expected_location.as_str())
        );
    }

    #[test]
    fn login_without_clientid_returns_bad_request() {
        // Arrange
        let t = build_rocket_test_instance();
        let client = Client::tracked(t.rocket).expect("valid rocket instance");
        let state = random_string(8, None);
        let redirect_uri = String::from("https://front.end.server/auth/callback");

        // Act
        let response = client
            .get(format!(
                "/login?state={}&redirect_uri={}",
                state, redirect_uri
            ))
            .dispatch();

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().unwrap(),
            "{\"message\": \"client_id is missing\"}"
        );
    }

    #[test]
    fn login_without_state_returns_bad_request() {
        // Arrange
        let t = build_rocket_test_instance();
        let client = Client::tracked(t.rocket).expect("valid rocket instance");
        let client_id = random_string(32, None);
        let redirect_uri = String::from("https://front.end.server/auth/callback");

        // Act
        let response = client
            .get(format!(
                "/login?client_id={}&redirect_uri={}",
                client_id, redirect_uri
            ))
            .dispatch();

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().unwrap(),
            "{\"message\": \"state is missing\"}"
        );
    }

    #[test]
    fn login_without_redirect_uri_returns_bad_request() {
        // Arrange
        let t = build_rocket_test_instance();
        let client = Client::tracked(t.rocket).expect("valid rocket instance");
        let state = random_string(8, None);
        let client_id = random_string(32, None);

        // Act
        let response = client
            .get(format!("/login?state={}&client_id={}", state, client_id))
            .dispatch();

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().unwrap(),
            "{\"message\": \"redirect_uri is missing\"}"
        );
    }
}
