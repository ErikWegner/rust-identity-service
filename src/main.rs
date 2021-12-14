use std::ops::Deref;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use oidcclient::{get_client_token, ClientCredentials, OidcClientState};
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

type HealthMap = DashMap<String, String>;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct HealthResponse {
    faults: HashMap<String, String>,
}

struct LoginConfiguration {
    authorization_endpoint: String,
}

impl Clone for LoginConfiguration {
    fn clone(&self) -> Self {
        Self {
            authorization_endpoint: self.authorization_endpoint.clone(),
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

fn build_rocket_instance(
    healthmap: Arc<HealthMap>,
    login_configuration: LoginConfiguration,
) -> Rocket<Build> {
    rocket::build()
        .manage(healthmap)
        .manage(login_configuration)
        .mount("/", routes![up, health, login])
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
    let oidc_client_state = Arc::new(OidcClientState::init(ClientCredentials {
        client_id: String::from("TODO"),
        client_secret: String::from("TODO"),
        token_url: String::from("TODO"),
    }));
    let login_configuration = LoginConfiguration {
        authorization_endpoint: String::from("TODO"),
    };
    client_token_thread(healthmap.clone(), oidc_client_state);
    build_rocket_instance(healthmap, login_configuration)
}

mod oidcclient;
#[cfg(test)]
mod tests;
