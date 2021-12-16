use std::collections::BTreeMap;
use std::ops::Deref;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use jwt::{Claims, PKeyWithDigest, SigningAlgorithm, Token, VerifyWithKey};
use jwt::{Header, SignWithKey};
use oidcclient::{acg_flow_step_2, get_client_token, ClientCredentials, OidcClientState};
use openssl::pkey::{Private, Public};
use rocket::form::Form;
use rocket::response::Redirect;
use rocket::serde::{Deserialize, Serialize};
use rocket::{
    http::Status,
    response::{content, status},
    Build, Rocket, State,
};
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

struct LoginConfiguration {
    authorization_endpoint: String,
    client_credentials: ClientCredentials,
    verification_key: Option<PKeyWithDigest<Public>>,
    issuer: String,
    issuing_key: Option<PKeyWithDigest<Private>>,
}

impl Clone for LoginConfiguration {
    fn clone(&self) -> Self {
        Self {
            authorization_endpoint: self.authorization_endpoint.clone(),
            client_credentials: self.client_credentials.clone(),
            verification_key: self.verification_key.as_ref().map(|vk| PKeyWithDigest {
                digest: vk.digest,
                key: vk.key.clone(),
            }),
            issuer: self.issuer.clone(),
            issuing_key: self.issuing_key.as_ref().map(|i| PKeyWithDigest {
                digest: i.digest,
                key: i.key.clone(),
            }),
        }
    }
}

fn construct_redirect_uri(
    login_configuration: LoginConfiguration,
    client_id: String,
    state: String,
    redirect_uri: String,
) -> String {
    String::from(
        url::Url::parse_with_params(
            &(login_configuration.authorization_endpoint),
            &[
                ("response_type", "code"),
                ("client_id", client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("scope", "openid"),
                ("state", state.as_str()),
            ],
        )
        .unwrap()
        .as_str(),
    )
}

fn create_token_string(issuer: &str, subject: &str, key: &impl SigningAlgorithm) -> String {
    let mut claims = BTreeMap::new();
    claims.insert("iss", issuer);
    claims.insert("sub", subject);

    claims.sign_with_key(key).unwrap()
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
    state_login_configuration: &State<LoginConfiguration>,
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
    let login_configuration: LoginConfiguration = state_login_configuration.deref().clone();
    Ok(Redirect::to(construct_redirect_uri(
        login_configuration,
        client_id.unwrap(),
        state.unwrap(),
        redirect_uri.unwrap(),
    )))
}

#[derive(FromForm)]
struct CallbackData<'r> {
    redirect_uri: &'r str,
    code: &'r str,
}

#[post("/callback", data = "<user_input>")]
async fn callback(
    user_input: Option<Form<CallbackData<'_>>>,
    state_login_configuration: &State<LoginConfiguration>,
) -> Result<String, status::Custom<content::Json<String>>> {
    if user_input.is_none() {
        return Err(status::Custom(
            Status::BadRequest,
            content::Json("{\"message\": \"cannot parse body\"}".to_string()),
        ));
    }
    let g = user_input.unwrap();
    let login_configuration: LoginConfiguration = state_login_configuration.deref().clone();
    let res = acg_flow_step_2(
        login_configuration.client_credentials,
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
            let token: Result<Token<Header, Claims, _>, jwt::Error> = internal_token
                .as_str()
                .verify_with_key(&login_configuration.verification_key.unwrap());
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
                    let subject = claims.registered.subject.as_ref().unwrap().as_str();
                    Ok(create_token_string(
                        login_configuration.issuer.as_str(),
                        subject,
                        &login_configuration.issuing_key.unwrap(),
                    ))
                }
            }
        }
    }
}

fn build_rocket_instance(
    healthmap: Arc<HealthMap>,
    login_configuration: LoginConfiguration,
) -> Rocket<Build> {
    rocket::build()
        .manage(healthmap)
        .manage(login_configuration)
        .mount("/", routes![up, health, login, callback])
}

fn client_token_thread(healthmap: Arc<HealthMap>, oidc_client_state_p: Arc<OidcClientState>) {
    let threadhealthmap = healthmap;
    let oidc_client_state = oidc_client_state_p;
    tokio::spawn(async move {
        let key = "oidclogin".to_string();
        loop {
            let _ = get_client_token(&oidc_client_state).await;
            threadhealthmap.insert(key.clone(), "OK".to_string());
            sleep(Duration::from_secs(2)).await;
            threadhealthmap.insert(key.clone(), "login failed".to_string());
            sleep(Duration::from_secs(2)).await;
        }
    });
}

#[launch]
fn rocket() -> _ {
    let healthmap = Arc::new(HealthMap::new());
    let client_credentials = Arc::new(ClientCredentials {
        client_id: String::from("TODO"),
        client_secret: String::from("TODO"),
        token_url: String::from("TODO"),
    });
    let oidc_client_state = Arc::new(OidcClientState::init(&client_credentials));
    let login_configuration = LoginConfiguration {
        authorization_endpoint: String::from("TODO"),
        client_credentials: client_credentials.deref().clone(),
        verification_key: None,
        issuer: String::from("TODO"),
        issuing_key: None,
    };
    client_token_thread(healthmap.clone(), oidc_client_state);
    build_rocket_instance(healthmap, login_configuration)
}

mod oidcclient;
#[cfg(test)]
mod tests;
