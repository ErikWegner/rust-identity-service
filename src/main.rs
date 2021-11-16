use std::env;

use dotenv::dotenv;
use ridser::init_openid_provider;

#[macro_use] extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    init_openid_provider().unwrap();
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    rocket::build().mount("/", routes![index])
}
