mod redisconn;
mod redismock;

use std::sync::{Arc, Mutex};

use crate::redisconn::get_redis_connection;
pub(crate) use dotenv::dotenv;
use redisconn::DataProvider;
use ridser::{cfg::RuntimeConfiguration, construct_redirect_uri, init_openid_provider};
use rocket::{Build, Rocket, State, http::Status, response::{Redirect, content, status::{self, BadRequest}}};

#[macro_use]
extern crate rocket;

struct SharedRedis {
    redis: Arc<Mutex<Box<dyn DataProvider>>>,
}

#[get("/up")]
fn up() -> &'static str {
    "OK"
}

#[get("/health")]
fn health(shared_con: &State<SharedRedis>) -> Result<&'static str, Status> {
    // TODO: redis::ConnectionLike.check_connection()
    let lockable_redis = Arc::clone(&shared_con.redis);
    let mut lock = lockable_redis.lock().expect("lock shared cache failed");
    if !lock.check_connection() {
        return Err(Status::InternalServerError);
    }
    Ok("OK")
}

#[get("/login?<client_id>&<state>")]
fn login(
    client_id: Option<String>,
    state: Option<String>,
    rc: &State<RuntimeConfiguration>,
    shared_con: &State<SharedRedis>,
) -> Result<Redirect, status::Custom<content::Json<&'static str>>> {
    if client_id.is_none() {
        return Err(status::Custom(Status::BadRequest, content::Json("{\"message\": \"client_id is missing\"}")));
    }
    let lockable_redis = Arc::clone(&shared_con.redis);
    let mut lock = lockable_redis.lock().expect("lock shared cache failed");
    let _: () = lock
        .set_int("my_key".to_string(), 42)
        .unwrap_or_else(|_| panic!("Could not write to cache."));
    Ok(Redirect::to(construct_redirect_uri(
        rc,
        client_id.unwrap().as_str(),
        state.unwrap().as_str(),
    )))
}

#[get("/callback")]
fn callback() -> String {
    String::from("not implemented yet")
}

fn build_rocket_instance(rc: RuntimeConfiguration, conn: Box<dyn DataProvider>) -> Rocket<Build> {
    rocket::build()
        .manage(rc)
        .manage(SharedRedis {
            redis: Arc::new(Mutex::new(conn)),
        })
        .mount("/", routes![up, health, login, callback])
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    let rc = init_openid_provider().unwrap();
    let conn = get_redis_connection().unwrap();
    build_rocket_instance(rc, Box::new(conn))
}

#[cfg(test)]
mod tests;
