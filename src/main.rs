mod oidcclient;
mod redisconn;

use crossbeam::channel::{unbounded, Sender};
use oidcclient::{
    get_auth_token, get_auth_token_dep, make_request_to_oidc_provider, request_mutex, HolderState,
    TokenData,
};
use parking_lot::{Condvar, Mutex};
use std::sync::Arc;

use crate::redisconn::get_redis_connection;
pub(crate) use dotenv::dotenv;
use redisconn::DataProvider;
use ridser::{cfg::RuntimeConfiguration, construct_redirect_uri, init_openid_provider};
use rocket::{
    http::Status,
    response::{content, status, Redirect},
    serde::json::Json,
    Build, Rocket, State,
};

#[macro_use]
extern crate rocket;

struct SharedRedis {
    redis: Arc<futures::lock::Mutex<Box<dyn DataProvider>>>,
}

#[get("/up")]
fn up() -> &'static str {
    "OK"
}

#[get("/health")]
async fn health(
    shared_con: &State<SharedRedis>,
) -> Result<&'static str, status::Custom<content::Json<&'static str>>> {
    // TODO: redis::ConnectionLike.check_connection()
    let lockable_redis = Arc::clone(&shared_con.redis);
    let mut lock = lockable_redis.lock().await;
    if !(lock.check_connection().await) {
        return Err(status::Custom(
            Status::InternalServerError,
            content::Json("{\"message\": \"redis disconnected\"}"),
        ));
    }
    Ok("OK")
}

#[get("/login?<client_id>&<state>")]
async fn login(
    client_id: Option<String>,
    state: Option<String>,
    rc: &State<RuntimeConfiguration>,
    shared_con: &State<SharedRedis>,
) -> Result<Redirect, status::Custom<content::Json<&'static str>>> {
    if client_id.is_none() {
        return Err(status::Custom(
            Status::BadRequest,
            content::Json("{\"message\": \"client_id is missing\"}"),
        ));
    }
    let lockable_redis = Arc::clone(&shared_con.redis);
    let mut lock = lockable_redis.lock().await;
    let _: () = lock
        .set_int("my_key".to_string(), 42)
        .await
        .unwrap_or_else(|_| panic!("Could not write to cache."));
    Ok(Redirect::to(construct_redirect_uri(
        rc,
        client_id.unwrap().as_str(),
        state.unwrap().as_str(),
    )))
}

#[post("/callback_dep")]
async fn callback_dep() -> Json<TokenData> {
    let t = get_auth_token_dep().await;
    Json(t)
}

#[post("/callback")]
async fn callback(
    managed_mutex: &State<Arc<(Mutex<HolderState>, Condvar)>>,
    managed_sender: &State<Sender<u8>>,
) -> Result<Json<TokenData>, status::Custom<content::Json<String>>> {
    let mutex = managed_mutex.inner().clone();
    let s = managed_sender.inner().clone();
    let t = get_auth_token(mutex, s).await;

    match t {
        Ok(r) => Ok(Json(r)),
        Err(msg) => Err(status::Custom(
            Status::InternalServerError,
            content::Json(format!("{{\"message\": \"{}\"}}", msg)),
        )),
    }
}

fn build_rocket_instance(
    rc: RuntimeConfiguration,
    conn: Box<dyn DataProvider>,
    mutex: Arc<(Mutex<HolderState>, Condvar)>,
    sender: Sender<u8>,
) -> Rocket<Build> {
    rocket::build()
        .manage(rc)
        .manage(SharedRedis {
            redis: Arc::new(futures::lock::Mutex::new(conn)),
        })
        .manage(mutex)
        .manage(sender)
        .mount("/", routes![up, health, login, callback])
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();
    let rc = init_openid_provider().unwrap();
    let conn = get_redis_connection().await.expect("Redis failed");
    let mutex = request_mutex();
    let (s, _r) = unbounded::<u8>();
    build_rocket_instance(rc, Box::new(conn), mutex, s)
}

#[cfg(test)]
mod redismock;

#[cfg(test)]
mod tests;
