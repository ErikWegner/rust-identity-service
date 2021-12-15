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
fn build_rocket_test_instance(token_url: Option<String>) -> TestEnv {
    let health_map = Arc::new(HealthMap::new());
    let login_configuration = LoginConfiguration {
        authorization_endpoint: format!(
            "{}/auth/login",
            random_string(64, Some(String::from("http://unit-test-url/")))
        ),
        client_credentials: ClientCredentials {
            token_url: token_url.unwrap_or_else(|| {
                random_string(14, Some("http://unit-test-url/token/".to_string()))
            }),
            client_id: random_string(12, None),
            client_secret: random_string(24, Some("Secret".to_string())),
        },
    };
    TestEnv {
        rocket: build_rocket_instance(health_map.clone(), login_configuration.clone()),
        health_map,
        login_configuration,
    }
}

#[test]
fn up() {
    let t = build_rocket_test_instance(None);
    let client = Client::tracked(t.rocket).expect("valid rocket instance");
    let response = client.get("/up").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some("OK".into()));
}

#[test]
fn health_simple_ok() {
    let t = build_rocket_test_instance(None);
    t.health_map.clear();
    t.health_map.insert("con".to_string(), "OK".to_string());
    let client = Client::tracked(t.rocket).expect("valid rocket instance");
    let response = client.get("/health").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some("OK".into()));
}

#[test]
fn health_simple_fail() {
    let t = build_rocket_test_instance(None);
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
    let token_endpoint_path = random_string(12, Some("/provider/path-".to_string()));
    let token = random_string(12, None);
    let client_credentials = ClientCredentials {
        client_id: "MockClient".to_string(),
        client_secret: "Mock Secret 123".to_string(),
        token_url: format!("{}{}", mock_server.uri(), token_endpoint_path),
    };
    let oidc_client_state = Arc::new(OidcClientState::init(&client_credentials));
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
        let t = build_rocket_test_instance(None);
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
        let t = build_rocket_test_instance(None);
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
        let t = build_rocket_test_instance(None);
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
        let t = build_rocket_test_instance(None);
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

mod callback {
    use jwt::{Claims, Header, Token};
    use rocket::{
        http::{ContentType, Status},
        local::blocking::Client,
    };
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{build_rocket_test_instance, random_string};

    fn callback_body(redirect_uri: String, code: String) -> String {
        format!("redirect_uri={}&code={}", redirect_uri, code)
    }

    #[test]
    fn callback_creates_bad_request_for_empty_body() {
        // Arrange
        let t = build_rocket_test_instance(None);
        let client = Client::tracked(t.rocket).expect("valid rocket instance");

        // Act
        let response = client.post("/callback").body("").dispatch();

        // Assert
        assert_eq!(
            response.status(),
            Status::BadRequest,
            "{}",
            response.into_string().unwrap()
        );
        assert_eq!(
            response.into_string().unwrap(),
            "{\"message\": \"cannot parse body\"}"
        );
    }

    #[test]
    fn callback_returns_token() {
        // Arrange
        let redirect_uri = String::from("https://front.end.server/auth/callback");
        let code = random_string(24, None);
        let mock_server = tokio_test::block_on(MockServer::start());
        let token_endpoint_path = random_string(12, Some("/provider/path-".to_string()));
        let token = String::from(
            "{\"access_token\":\"\
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzY0NDAyOTQsIml\
hdCI6MTYzNjQzOTk5NCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLm9yZy8iLCJzdWIi\
OiI2Y2MyZDFkMy0zOGVkLTQ0OWEtOTkzMy1lNzFkNTE1OGM1YTAiLCJ0eXAiOiJCZ\
WFyZXIiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIn0.dEDyLww3fAlttE\
yecqeJoZtgo1tHNpcK-fF3ScDlQmzT-OMVJKlbiWq2ihxQ1KVX-zi80wEbRu5mxht\
SltfoV2LJoJGxLUhTBgw1ip_NMojF2GuSfDBGpPX3nYFYvAJRKdL8E0pS_hPrMRqh\
wFjJJWYGPlrbre99173ZqZTlB0GAAfUC65533MFtL1CegxfqZiYJ3MY2ZxpCUWBdg\
XTVjOyz-3iJGZdCxQts_H4toE6i2mVSu5wNvJEl0FibR2Lwer1wvFMTksR56hioCf\
ongesHz2kaQYrlntHD4zH3OOW79qZ5Jvb1O326a39RioQiJMaCElDY3psi4xXCTaY\
95g\"}",
        );
        tokio_test::block_on(
            Mock::given(method("POST"))
                .and(path(&token_endpoint_path))
                .respond_with(ResponseTemplate::new(200).set_body_string(&token))
                .mount(&mock_server),
        );
        let t = build_rocket_test_instance(Some(format!(
            "{}{}",
            mock_server.uri(),
            token_endpoint_path
        )));
        let client = Client::tracked(t.rocket).expect("valid rocket instance");

        // Act
        let response = client
            .post("/callback")
            .header(ContentType::Form)
            .body(callback_body(redirect_uri, code))
            .dispatch();

        // Assert
        let status = response.status();
        let te = response.into_string().unwrap();
        assert_eq!(status, Status::Ok, "{}", te);
        let responsetoken: Token<Header, Claims, _> = Token::parse_unverified(te.as_str()).unwrap();

        assert_eq!(
            responsetoken
                .claims()
                .registered
                .subject
                .as_ref()
                .unwrap()
                .as_str(),
            "6cc2d1d3-38ed-449a-9933-e71d5158c5a0"
        );
    }
}
