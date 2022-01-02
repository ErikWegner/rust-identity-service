use std::env;
use std::sync::Arc;

use crate::oidcclient::{get_client_token, ClientCredentials, OidcClientState, TokenResponse};
use crate::redis::Redis;
use crate::{build_rocket_instance, load_key, HealthMap, LoginConfiguration};

use super::rocket;
use jwt::PKeyWithDigest;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rocket::http::Status;
use rocket::local::asynchronous::Client;
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
    oidc_client_state: Arc<OidcClientState>,
    token_endpoint_path: String,
    group_query_path: String,
}

pub(crate) fn get_redis() -> Redis {
    let c = env::var("RIDSER_REDIS_CONNECTION").unwrap_or_else(|_| "redis://redis/".to_string());
    Redis::new(c.as_str())
}

fn random_string(length: usize, prefix: Option<String>) -> String {
    let rs = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(|c| c as char)
        .collect::<String>();
    format!("{}{}", prefix.unwrap_or_default(), rs)
}

fn build_rocket_test_instance(mock_server_uri: Option<String>, issuer: &str) -> TestEnv {
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
    let uri_base = mock_server_uri
        .unwrap_or_else(|| random_string(14, Some("http://unit-test-url/token/".to_string())));
    let token_endpoint_path = random_string(12, Some("/provider/path-".to_string()));
    let group_query_path = random_string(12, Some("/groups/{SUBJECT}/path-".to_string()));
    let client_credentials = Arc::new(ClientCredentials {
        token_url: format!("{}{}", uri_base, token_endpoint_path),
        client_id: random_string(12, None),
        client_secret: random_string(24, Some("Secret".to_string())),
    });
    let login_configuration = Arc::new(LoginConfiguration {
        authorization_endpoint: format!(
            "{}/auth/login",
            random_string(64, Some(String::from("http://unit-test-url/")))
        ),
        client_credentials: client_credentials.clone(),
        verification_key,
        issuer: String::from(issuer),
        issuing_key,
        group_query_url: format!("{}{}", uri_base, group_query_path),
    });
    let oidc_client_state = Arc::new(OidcClientState::new(client_credentials));
    let redis = Arc::new(get_redis());
    TestEnv {
        rocket: build_rocket_instance(
            health_map.clone(),
            login_configuration.clone(),
            oidc_client_state.clone(),
            redis,
        ),
        health_map,
        login_configuration,
        oidc_client_state,
        token_endpoint_path,
        group_query_path,
    }
}

#[tokio::test]
async fn up() {
    let t = build_rocket_test_instance(None, "unittest");
    let client = Client::tracked(t.rocket)
        .await
        .expect("valid rocket instance");
    let response = client.get("/up").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().await, Some("OK".into()));
}

#[tokio::test]
async fn health_simple_ok() {
    let t = build_rocket_test_instance(None, "unittest");
    t.health_map.clear();
    t.health_map.insert("con".to_string(), "OK".to_string());
    let client = Client::tracked(t.rocket)
        .await
        .expect("valid rocket instance");
    let response = client.get("/health").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().await, Some("OK".into()));
}

#[tokio::test]
async fn health_simple_fail() {
    let t = build_rocket_test_instance(None, "unittest");
    t.health_map.clear();
    t.health_map
        .insert("con".to_string(), "failed to connect".to_string());
    let client = Client::tracked(t.rocket)
        .await
        .expect("valid rocket instance");
    let response = client.get("/health").dispatch().await;
    assert_eq!(response.status(), Status::BadGateway);
    assert_eq!(
        response.into_string().await,
        Some("{\"faults\":{\"con\":\"failed to connect\"}}".into())
    );
}

#[tokio::test]
async fn retrieve_token_returns_token() {
    // Arrange
    // Start a background HTTP server on a random local port
    let mock_server = MockServer::start().await;
    let token_endpoint_path = random_string(12, Some("/provider/path-".to_string()));
    let access_token = random_string(12, None);
    let token_mock_response = TokenResponse {
        access_token: access_token.clone(),
    };
    let client_credentials = Arc::new(ClientCredentials {
        client_id: "MockClient".to_string(),
        client_secret: "Mock Secret 123".to_string(),
        token_url: format!("{}{}", mock_server.uri(), token_endpoint_path),
    });
    let oidc_client_state = Arc::new(OidcClientState::new(client_credentials));

    Mock::given(method("POST"))
        .and(path(&token_endpoint_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                serde_json::to_string(&token_mock_response)
                    .unwrap()
                    .as_str(),
            ),
        )
        .mount(&mock_server)
        .await;

    // Act
    let r = get_client_token(oidc_client_state).await;

    // Assert
    assert_ok!(&r);
    let tokenresult = r.unwrap();
    assert_eq!(tokenresult, access_token);
}

mod login {
    use rocket::{http::Status, local::asynchronous::Client};

    use crate::tests::{build_rocket_test_instance, random_string};

    #[tokio::test]
    async fn login_returns_redirect() {
        // Arrange
        let t = build_rocket_test_instance(None, "unittest");
        let client = Client::tracked(t.rocket)
            .await
            .expect("valid rocket instance");
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
            .dispatch()
            .await;

        // Assert
        assert_eq!(
            response.status(),
            Status::SeeOther,
            "{}",
            response.into_string().await.unwrap()
        );
        assert!(response.headers().contains("Location"));
        assert_eq!(
            response.headers().get_one("Location"),
            Some(expected_location.as_str())
        );
    }

    #[tokio::test]
    async fn login_without_clientid_returns_bad_request() {
        // Arrange
        let t = build_rocket_test_instance(None, "unittest");
        let client = Client::tracked(t.rocket)
            .await
            .expect("valid rocket instance");
        let state = random_string(8, None);
        let redirect_uri = String::from("https://front.end.server/auth/callback");

        // Act
        let response = client
            .get(format!(
                "/login?state={}&redirect_uri={}",
                state, redirect_uri
            ))
            .dispatch()
            .await;

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().await.unwrap(),
            "{\"message\": \"client_id is missing\"}"
        );
    }

    #[tokio::test]
    async fn login_without_state_returns_bad_request() {
        // Arrange
        let t = build_rocket_test_instance(None, "unittest");
        let client = Client::tracked(t.rocket)
            .await
            .expect("valid rocket instance");
        let client_id = random_string(32, None);
        let redirect_uri = String::from("https://front.end.server/auth/callback");

        // Act
        let response = client
            .get(format!(
                "/login?client_id={}&redirect_uri={}",
                client_id, redirect_uri
            ))
            .dispatch()
            .await;

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().await.unwrap(),
            "{\"message\": \"state is missing\"}"
        );
    }

    #[tokio::test]
    async fn login_without_redirect_uri_returns_bad_request() {
        // Arrange
        let t = build_rocket_test_instance(None, "unittest");
        let client = Client::tracked(t.rocket)
            .await
            .expect("valid rocket instance");
        let state = random_string(8, None);
        let client_id = random_string(32, None);

        // Act
        let response = client
            .get(format!("/login?state={}&client_id={}", state, client_id))
            .dispatch()
            .await;

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().await.unwrap(),
            "{\"message\": \"redirect_uri is missing\"}"
        );
    }
}

mod callback {
    use std::{collections::BTreeMap, vec};

    use jwt::{AlgorithmType, Claims, Header, PKeyWithDigest, SignWithKey, Token, VerifyWithKey};
    use openssl::{hash::MessageDigest, pkey::PKey};
    use rocket::{
        http::{ContentType, Status},
        local::asynchronous::Client,
    };
    use serde_json::json;
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

    #[tokio::test]
    async fn callback_creates_bad_request_for_empty_body() {
        // Arrange
        let t = build_rocket_test_instance(None, "unittest");
        let client = Client::tracked(t.rocket)
            .await
            .expect("valid rocket instance");

        // Act
        let response = client.post("/callback").body("").dispatch().await;

        // Assert
        assert_eq!(
            response.status(),
            Status::BadRequest,
            "{}",
            response.into_string().await.unwrap()
        );
        assert_eq!(
            response.into_string().await.unwrap(),
            "{\"message\": \"cannot parse body\"}"
        );
    }

    #[tokio::test]
    async fn callback_returns_token() {
        // Arrange
        let redirect_uri = String::from("https://front.end.server/auth/callback");
        let code = random_string(24, None);
        let mock_server = MockServer::start().await;

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
        let t = build_rocket_test_instance(Some(mock_server.uri()), second_issuer.as_str());
        // Wiremock: second part of OpenID Connect

        Mock::given(method("POST"))
            .and(path(&t.token_endpoint_path))
            .respond_with(ResponseTemplate::new(200).set_body_string(&token))
            .mount(&mock_server)
            .await;
        // Wiremock: group membership for user

        Mock::given(method("GET"))
                .and(path(&t.group_query_path.replace("{SUBJECT}", user_id.as_str())))
                .respond_with(ResponseTemplate::new(200).set_body_string(r#"[{"id":"1e1ca5a8-9162-43ff-b318-c7d293ca2441","name":"Group1","path":"/Group1"},{"id":"475b26d8-398b-468d-b703-7d448987e1c3","name":"Group2","path":"/Group2"},{"id":"de383b7d-cbe0-4435-80ed-20f19014e240","name":"Group4","path":"/Group3/Group4"}]"#))
                .mount(&mock_server).await;
        let client = Client::tracked(t.rocket)
            .await
            .expect("valid rocket instance");
        {
            let mut w = t.oidc_client_state.query_token.write();
            *w = Some("zork".to_string());
        }

        // Act
        let response = client
            .post("/callback")
            .header(ContentType::Form)
            .body(callback_body(redirect_uri, code))
            .dispatch()
            .await;

        // Assert
        let status = response.status();
        let te = response.into_string().await.unwrap();
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
        let tr = responsetoken
            .claims()
            .private
            .get("roles")
            .expect("No roles-claim in token");
        assert_eq!(*tr, json!(vec!["Group1".to_string(), "Group2".to_string()]))
    }
}
