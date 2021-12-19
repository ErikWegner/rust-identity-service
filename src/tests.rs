use std::sync::Arc;

use crate::oidcclient::{get_client_token, ClientCredentials, OidcClientState};
use crate::{build_rocket_instance, load_key, HealthMap, LoginConfiguration};

use super::rocket;
use jwt::PKeyWithDigest;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rocket::http::Status;
use rocket::local::blocking::Client;
use rocket::{Build, Rocket};
use tokio_test::assert_ok;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/** A token from the remote authentication system is signed with this key */
const UNITTEST_TRUSTED_KEYFILE: &str = "./test.pem";
const UNITTEST_TRUSTED_PUBKEYFILE: &str = "./testpublic.pem";
/** A self issued token is signed with this key */
const UNITTEST_ISSUER_KEYFILE: &str = "./test2.pem";
const UNITTEST_ISSUER_PUBKEYFILE: &str = "./testpublic2.pem";

struct TestEnv {
    rocket: Rocket<Build>,
    health_map: Arc<HealthMap>,
    login_configuration: Arc<LoginConfiguration>,
}

fn random_string(length: usize, prefix: Option<String>) -> String {
    let rs = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(|c| c as char)
        .collect::<String>();
    format!("{}{}", prefix.unwrap_or_default(), rs)
}

fn build_rocket_test_instance(token_url: Option<String>, issuer: &str) -> TestEnv {
    let health_map = Arc::new(HealthMap::new());
    let verification_key_content = load_key(UNITTEST_TRUSTED_PUBKEYFILE);
    let verification_key = Arc::new(PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::public_key_from_pem(verification_key_content.as_bytes()).unwrap(),
    });
    let issuing_key_content = load_key(UNITTEST_ISSUER_KEYFILE);
    let issuing_key = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::private_key_from_pem(issuing_key_content.as_bytes()).unwrap(),
    };
    let login_configuration = Arc::new(LoginConfiguration {
        authorization_endpoint: format!(
            "{}/auth/login",
            random_string(64, Some(String::from("http://unit-test-url/")))
        ),
        client_credentials: Arc::new(ClientCredentials {
            token_url: token_url.unwrap_or_else(|| {
                random_string(14, Some("http://unit-test-url/token/".to_string()))
            }),
            client_id: random_string(12, None),
            client_secret: random_string(24, Some("Secret".to_string())),
        }),
        verification_key,
        issuer: String::from(issuer),
        issuing_key,
    });
    TestEnv {
        rocket: build_rocket_instance(health_map.clone(), login_configuration.clone()),
        health_map,
        login_configuration,
    }
}

#[test]
fn up() {
    let t = build_rocket_test_instance(None, "unittest");
    let client = Client::tracked(t.rocket).expect("valid rocket instance");
    let response = client.get("/up").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some("OK".into()));
}

#[test]
fn health_simple_ok() {
    let t = build_rocket_test_instance(None, "unittest");
    t.health_map.clear();
    t.health_map.insert("con".to_string(), "OK".to_string());
    let client = Client::tracked(t.rocket).expect("valid rocket instance");
    let response = client.get("/health").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), Some("OK".into()));
}

#[test]
fn health_simple_fail() {
    let t = build_rocket_test_instance(None, "unittest");
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
    let client_credentials = Arc::new(ClientCredentials {
        client_id: "MockClient".to_string(),
        client_secret: "Mock Secret 123".to_string(),
        token_url: format!("{}{}", mock_server.uri(), token_endpoint_path),
    });
    let oidc_client_state = Arc::new(OidcClientState::new(client_credentials));
    tokio_test::block_on(
        Mock::given(method("POST"))
            .and(path(&token_endpoint_path))
            .respond_with(ResponseTemplate::new(200).set_body_string(&token))
            .mount(&mock_server),
    );

    // Act
    let r = tokio_test::block_on(get_client_token(oidc_client_state));

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
        let t = build_rocket_test_instance(None, "unittest");
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
        let t = build_rocket_test_instance(None, "unittest");
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
        let t = build_rocket_test_instance(None, "unittest");
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
        let t = build_rocket_test_instance(None, "unittest");
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
    use std::collections::BTreeMap;

    use jwt::{AlgorithmType, Claims, Header, PKeyWithDigest, SignWithKey, Token, VerifyWithKey};
    use openssl::{hash::MessageDigest, pkey::PKey};
    use rocket::{
        http::{ContentType, Status},
        local::blocking::Client,
    };
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::{load_key, oidcclient::TokenResponse, tests::UNITTEST_ISSUER_PUBKEYFILE};

    use super::{build_rocket_test_instance, random_string, UNITTEST_TRUSTED_KEYFILE};

    fn new_token(user_id: &str, iss: &str) -> String {
        let key = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::private_key_from_pem(load_key(UNITTEST_TRUSTED_KEYFILE).as_bytes()).unwrap(),
        };
        let header = Header {
            algorithm: AlgorithmType::Rs256,
            ..Default::default()
        };

        let mut claims = BTreeMap::new();

        claims.insert("iss", iss);
        claims.insert("sub", user_id);

        let signed_token = Token::new(header, claims)
            .sign_with_key(&key)
            .expect("Cannot sign new token.");
        signed_token.as_str().to_string()
    }

    fn callback_body(redirect_uri: String, code: String) -> String {
        format!("redirect_uri={}&code={}", redirect_uri, code)
    }

    #[test]
    fn callback_creates_bad_request_for_empty_body() {
        // Arrange
        let t = build_rocket_test_instance(None, "unittest");
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
        let user_id = random_string(8, Some("user-".to_string()));
        let second_issuer = random_string(12, Some("issuer2-".to_string()));
        let external_issuer = random_string(12, Some("externalissuer-".to_string()));
        let token = format!(
            "{{\"access_token\":\"{}\"}}",
            new_token(&user_id, &external_issuer)
        );

        let pubkey2 = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::public_key_from_pem(load_key(UNITTEST_ISSUER_PUBKEYFILE).as_bytes())
                .unwrap(),
        };
        tokio_test::block_on(
            Mock::given(method("POST"))
                .and(path(&token_endpoint_path))
                .respond_with(ResponseTemplate::new(200).set_body_string(&token))
                .mount(&mock_server),
        );
        let t = build_rocket_test_instance(
            Some(format!("{}{}", mock_server.uri(), token_endpoint_path)),
            second_issuer.as_str(),
        );
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
        let token_des = serde_json::from_str::<TokenResponse>(&te).expect("Deserialization failed");
        let responsetoken_verifyresult: Result<Token<Header, Claims, _>, _> =
            token_des.access_token.as_str().verify_with_key(&pubkey2);
        let responsetoken = responsetoken_verifyresult.expect("Verification failed");

        assert_eq!(
            responsetoken
                .claims()
                .registered
                .subject
                .as_ref()
                .unwrap()
                .as_str(),
            user_id
        );
        assert_eq!(
            responsetoken
                .claims()
                .registered
                .issuer
                .as_ref()
                .unwrap()
                .as_str(),
            second_issuer
        );
    }
}
