mod redisconn;

use std::sync::Mutex;

use crate::redisconn::get_redis_connection;
pub(crate) use dotenv::dotenv;
use ridser::{cfg::RuntimeConfiguration, construct_redirect_uri, init_openid_provider};
use rocket::{State, response::Redirect};

#[macro_use]
extern crate rocket;

extern crate redis;
use redis::Commands;

struct SharedRedis {
    redis: Mutex<redis::Connection>,
}

#[get("/up")]
fn up() -> &'static str {
    "OK"
}

#[get("/health")]
fn health(shared_con: &State<SharedRedis>) -> &'static str {
    // TODO: redis::ConnectionLike.check_connection()
    "OK"
}

#[get("/login")]
fn login(rc: &State<RuntimeConfiguration>, shared_con: &State<SharedRedis>) -> Redirect {
    let mut lock = shared_con.redis.lock().expect("lock shared cache failed");
    let _: () = lock
        .set("my_key", 42)
        .unwrap_or_else(|_| panic!("Could not write to cache."));
    Redirect::to(construct_redirect_uri(rc))
}

#[get("/callback")]
fn callback() -> String {
    String::from("not implemented yet")
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    let rc = init_openid_provider().unwrap();
    let conn = get_redis_connection().unwrap();
    rocket::build()
        .manage(rc)
        .manage(SharedRedis {
            redis: Mutex::new(conn),
        })
        .mount("/", routes![up, health, login, callback])
}
