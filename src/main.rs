use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
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

fn client_token_thread(healthmap: Arc<HealthMap>) {
    let threadhealthmap = healthmap;
    tokio::spawn(async move {
        let key = "oidclogin".to_string();
        loop {
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
    client_token_thread(healthmap.clone());
    build_rocket_instance(healthmap)
}

#[cfg(test)]
mod tests;
