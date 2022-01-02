use std::env;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use dotenv::dotenv;
use jwt::{Claims, PKeyWithDigest, RegisteredClaims, SigningAlgorithm, Token, VerifyWithKey};
use jwt::{Header, SignWithKey};
use oidcclient::{
    acg_flow_step_2, get_client_token, try_query_groups, ClientCredentials, OidcClientState,
};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::X509;
use redis::Redis;
use rocket::form::Form;
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{
    http::Status,
    response::{content, status},
    Build, Rocket, State,
};
use serde_json::json;
use tokio::time::sleep;

#[macro_use]
extern crate rocket;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct ErrorMessageResponse {
    message: String,
}

type HealthMap = DashMap<String, String>;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct HealthResponse {
    faults: HashMap<String, String>,
}

pub(crate) struct LoginConfiguration {
    authorization_endpoint: String,
    client_credentials: Arc<ClientCredentials>,
    verification_key: Arc<PKeyWithDigest<Public>>,
    issuer: String,
    issuing_key: PKeyWithDigest<Private>,
    group_query_url: String,
}

impl LoginConfiguration {
    fn cc(&self) -> Arc<ClientCredentials> {
        self.client_credentials.clone()
    }
}

fn construct_redirect_uri(
    login_configuration: &LoginConfiguration,
    client_id: &str,
    state: &str,
    redirect_uri: &str,
) -> String {
    String::from(
        url::Url::parse_with_params(
            &(login_configuration.authorization_endpoint),
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("scope", "openid"),
                ("state", state),
            ],
        )
        .unwrap()
        .as_str(),
    )
}

fn create_token_string(
    issuer: &str,
    subject: &str,
    key: &impl SigningAlgorithm,
    roles: Vec<String>,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires = now + 20 * 60;
    let mut claims = Claims::new(RegisteredClaims {
        issuer: Some(issuer.to_string()),
        subject: Some(subject.to_string()),
        audience: None,
        expiration: Some(expires),
        not_before: Some(now),
        issued_at: Some(now),
        json_web_token_id: None,
    });
    claims.private.insert("roles".to_string(), json!(roles));

    claims.sign_with_key(key).unwrap()
}

#[derive(Deserialize)]
struct OpenIdConfiguration {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct CertsX5CResponse {
    r#use: String,
    x5c: Vec<String>,
}

#[derive(Deserialize)]
struct CertsResponse {
    keys: Vec<CertsX5CResponse>,
}

struct EnvAndDiscoveryResult {
    group_query_url: String,
    internal_client_id: String,
    internal_client_secret: String,
    issuer: String,
    public_authorization_endpoint: String,
    redis_conn_string: String,
    signing_key: PKeyWithDigest<Private>,
    token_endpoint: String,
    verification_key: PKeyWithDigest<Public>,
}

async fn init_env() -> EnvAndDiscoveryResult {
    let group_query_url =
        env::var("RIDSER_GROUP_QUERY_URL").expect("Value for RIDSER_GROUP_QUERY_URL is not set.");
    let internal_client_id =
        env::var("RIDSER_CLIENT_ID").expect("Value for RIDSER_CLIENT_ID is not set.");
    let internal_client_secret =
        env::var("RIDSER_CLIENT_SECRET").expect("Value for RIDSER_CLIENT_SECRET is not set.");
    let issuer = env::var("RIDSER_ISSUER").expect("Value for RIDSER_ISSUER is not set.");
    let key_filename =
        env::var("RIDSER_SIGNING_KEY_FILE").expect("Value for RIDSER_SIGNING_KEY_FILE is not set.");
    let signing_key = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::private_key_from_pem(load_key(key_filename.as_str()).as_bytes()).unwrap(),
    };
    let dicovery_endpoint =
        env::var("RIDSER_METADATA_URL").expect("Value for RIDSER_METADATA_URL is not set.");
    let openid_configuration = reqwest::get(&dicovery_endpoint)
        .await
        .unwrap_or_else(|_| panic!("Endpoint {} could not be loaded", dicovery_endpoint))
        .json::<OpenIdConfiguration>()
        .await
        .unwrap_or_else(|_| panic!("Could not parse response from {}", dicovery_endpoint));
    let certs_uri = openid_configuration.jwks_uri;
    let certs_response = reqwest::get(&certs_uri)
        .await
        .unwrap_or_else(|_| panic!("Certificates could not be loaded from {}", certs_uri))
        .json::<CertsResponse>()
        .await
        .unwrap_or_else(|_| panic!("Could not parse response from {}", certs_uri));
    let certs_key = certs_response
        .keys
        .iter()
        .find_map(|f| {
            if f.r#use == "sig" {
                Some(format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    f.x5c[0]
                ))
            } else {
                None
            }
        })
        .expect("No verification key provided");
    let x509 = X509::from_pem(certs_key.as_bytes()).expect("Verification key parser error");
    let x509_public_key = x509.public_key();
    let verification_key = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: x509_public_key.expect("Verification key invalid"),
    };
    let redis_conn_string =
        env::var("RIDSER_REDIS_CONNECTION").expect("Value for RIDSER_REDIS_CONNECTION is not set.");
    EnvAndDiscoveryResult {
        group_query_url,
        internal_client_id,
        internal_client_secret,
        issuer,
        public_authorization_endpoint: env::var("RIDSER_PUBLIC_AUTHORIZATION_URL")
            .unwrap_or_else(|_| openid_configuration.authorization_endpoint.clone()),
        redis_conn_string,
        signing_key,
        token_endpoint: openid_configuration.token_endpoint,
        verification_key,
    }
}

fn load_key(keypath: &str) -> String {
    let mut key_file =
        File::open(keypath).unwrap_or_else(|_| panic!("Loading file {} failed", keypath));
    let mut key = String::new();
    key_file.read_to_string(&mut key).unwrap();
    key
}

#[get("/up")]
fn up() -> &'static str {
    "OK"
}

#[get("/health")]
fn health(
    healthmap: &State<Arc<HealthMap>>,
) -> Result<&'static str, status::Custom<content::Json<String>>> {
    let healthmap_iter = healthmap.iter();
    let faults = healthmap_iter
        .filter(|e| e.value() != "OK")
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect::<HashMap<_, _>>();

    if faults.is_empty() {
        return Ok("OK");
    }
    let j = HealthResponse { faults };
    Err(status::Custom(
        Status::BadGateway,
        content::Json(serde_json::to_string(&j).unwrap()),
    ))
}

#[get("/login?<client_id>&<state>&<redirect_uri>")]
async fn login(
    client_id: Option<String>,
    state: Option<String>,
    redirect_uri: Option<String>,
    state_login_configuration: &State<Arc<LoginConfiguration>>,
) -> Result<Redirect, status::Custom<content::Json<&'static str>>> {
    if client_id.is_none() {
        return Err(status::Custom(
            Status::BadRequest,
            content::Json("{\"message\": \"client_id is missing\"}"),
        ));
    }
    if state.is_none() {
        return Err(status::Custom(
            Status::BadRequest,
            content::Json("{\"message\": \"state is missing\"}"),
        ));
    }
    if redirect_uri.is_none() {
        return Err(status::Custom(
            Status::BadRequest,
            content::Json("{\"message\": \"redirect_uri is missing\"}"),
        ));
    }
    let login_configuration = state_login_configuration.deref();
    Ok(Redirect::to(construct_redirect_uri(
        login_configuration,
        &client_id.unwrap(),
        &state.unwrap(),
        &redirect_uri.unwrap(),
    )))
}

#[derive(FromForm)]
struct CallbackData<'r> {
    redirect_uri: &'r str,
    code: &'r str,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct JwtResponse {
    access_token: String,
    token_type: String,
}

#[post("/callback", data = "<user_input>")]
async fn callback(
    user_input: Option<Form<CallbackData<'_>>>,
    state_login_configuration: &State<Arc<LoginConfiguration>>,
    oidc_client_state: &State<Arc<OidcClientState>>,
    redis: &State<Arc<Redis>>,
) -> Result<Json<JwtResponse>, status::Custom<content::Json<String>>> {
    if user_input.is_none() {
        return Err(status::Custom(
            Status::BadRequest,
            content::Json("{\"message\": \"cannot parse body\"}".to_string()),
        ));
    }
    let g = user_input.unwrap();
    let login_configuration = state_login_configuration.deref().clone();
    let res = acg_flow_step_2(
        &login_configuration.cc(),
        g.redirect_uri.to_string(),
        g.code.to_string(),
    )
    .await;
    match res {
        Err(e) => {
            let emr = ErrorMessageResponse { message: e.1 };
            Err(status::Custom(
                Status::from_code(e.0).unwrap_or(Status::InternalServerError),
                content::Json(serde_json::to_string(&emr).unwrap()),
            ))
        }
        Ok(internal_token) => {
            let verification_key = login_configuration.verification_key.deref();
            let token: Result<Token<Header, Claims, _>, jwt::Error> =
                internal_token.as_str().verify_with_key(verification_key);
            match token {
                Err(e) => {
                    let emr = ErrorMessageResponse {
                        message: e.to_string(),
                    };
                    Err(status::Custom(
                        Status::InternalServerError,
                        content::Json(serde_json::to_string(&emr).unwrap()),
                    ))
                }
                Ok(tokendata) => {
                    let claims = tokendata.claims();
                    let subject = claims.registered.subject.as_ref().unwrap();
                    let issuing_key = &login_configuration.issuing_key;

                    let p = oidc_client_state.deref().clone();
                    let lock = p.query_token.read();
                    let o = &*lock;
                    let token: String = o.as_ref().unwrap().clone();
                    drop(lock);
                    let roles = try_query_groups(
                        subject,
                        login_configuration.group_query_url.as_str(),
                        token.as_str(),
                        redis,
                    )
                    .await;

                    Ok(Json(JwtResponse {
                        access_token: create_token_string(
                            &login_configuration.issuer,
                            subject,
                            issuing_key,
                            roles,
                        ),
                        token_type: "Bearer".to_string(),
                    }))
                }
            }
        }
    }
}

fn build_rocket_instance(
    healthmap: Arc<HealthMap>,
    login_configuration: Arc<LoginConfiguration>,
    oidc_client_state: Arc<OidcClientState>,
    redis: Arc<Redis>,
) -> Rocket<Build> {
    rocket::build()
        .manage(healthmap)
        .manage(login_configuration)
        .manage(oidc_client_state)
        .manage(redis)
        .mount("/", routes![up, health, login, callback])
}

fn client_token_thread(
    healthmap: Arc<HealthMap>,
    oidc_client_state_p: Arc<OidcClientState>,
    verification_key: Arc<PKeyWithDigest<Public>>,
) {
    let threadhealthmap = healthmap;
    let oidc_client_state = oidc_client_state_p;
    let mut next_retrieval_time: u64 = 0;
    tokio::spawn(async move {
        let key = "oidclogin".to_string();
        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now >= next_retrieval_time {
                let token_result = get_client_token(oidc_client_state.clone()).await;
                match token_result {
                    Ok(token) => {
                        {
                            let st = Some(token.clone());
                            let mut w = oidc_client_state.query_token.write();
                            *w = st;
                        }
                        threadhealthmap.insert(key.clone(), "OK".to_string());
                        next_retrieval_time =
                            calc_next_retrieval_time(token.as_str(), &verification_key);
                    }
                    Err(m) => {
                        {
                            let mut w = oidc_client_state.query_token.write();
                            *w = None;
                        }
                        threadhealthmap.insert(key.clone(), m);
                    }
                };
            }
            sleep(Duration::from_secs(2)).await;
        }
    });
}

fn calc_next_retrieval_time(token: &str, verification_key: &PKeyWithDigest<Public>) -> u64 {
    let r: Result<Token<Header, Claims, _>, jwt::Error> = token.verify_with_key(verification_key);
    // Substract ten seconds from expiration time
    match r {
        Ok(t) => t.claims().registered.expiration.unwrap() - 10,
        Err(_) => 0,
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();
    let discovery_result = init_env().await;
    let healthmap = Arc::new(HealthMap::new());
    let client_credentials = Arc::new(ClientCredentials {
        client_id: discovery_result.internal_client_id,
        client_secret: discovery_result.internal_client_secret,
        token_url: discovery_result.token_endpoint,
    });
    let oidc_client_state = Arc::new(OidcClientState::new(client_credentials.clone()));
    let verification_key_arc = Arc::new(discovery_result.verification_key);
    let login_configuration = LoginConfiguration {
        authorization_endpoint: discovery_result.public_authorization_endpoint,
        client_credentials,
        verification_key: verification_key_arc.clone(),
        issuer: discovery_result.issuer,
        issuing_key: discovery_result.signing_key,
        group_query_url: discovery_result.group_query_url,
    };
    client_token_thread(
        healthmap.clone(),
        oidc_client_state.clone(),
        verification_key_arc,
    );
    let redis_con = Redis::new(&discovery_result.redis_conn_string);
    let redis = Arc::new(redis_con);
    build_rocket_instance(
        healthmap,
        Arc::new(login_configuration),
        oidc_client_state,
        redis,
    )
    .attach(cors::Cors)
}

mod cors;
mod oidcclient;
mod redis;

#[cfg(test)]
mod tests;
