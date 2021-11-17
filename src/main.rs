use std::env;

use dotenv::dotenv;
use ridser::{cfg::RuntimeConfiguration, construct_redirect_uri, init_openid_provider};
use rocket::{State, response::Redirect};

#[macro_use] extern crate rocket;

#[get("/up")]
fn index() -> &'static str {
    "OK"
}

#[get("/login")]
fn login(rc: &State<RuntimeConfiguration>) -> Redirect {
    Redirect::to(construct_redirect_uri(rc))
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    let rc = init_openid_provider().unwrap();
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    rocket::build()
    .manage(rc)
    .mount("/", routes![index, login])
}
