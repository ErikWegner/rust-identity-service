use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use oidcclient::{get_client_token, ClientCredentials, OidcClientState};
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

fn build_rocket_instance(healthmap: Arc<HealthMap>) -> Rocket<Build> {
    rocket::build()
        .manage(healthmap)
        .mount("/", routes![up, health])
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
    client_token_thread(healthmap.clone(), oidc_client_state);
    build_rocket_instance(healthmap)
}

mod oidcclient;
#[cfg(test)]
mod tests;
