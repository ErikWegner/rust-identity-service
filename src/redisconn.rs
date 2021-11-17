use std::{env, error::Error};

pub fn get_redis_connection() -> Result<redis::Connection, Box<dyn Error>> {
    let redis_uri = env::var("RIDSER_REDIS_URI").expect("Value for RIDSER_REDIS_URI is not set.");
    let client =
        redis::Client::open(redis_uri.as_str()).unwrap_or_else(|_| panic!("Uri {} invalid.", redis_uri));
    let conn = client
        .get_connection()
        .unwrap_or_else(|_| panic!("Connection to {} failed.", redis_uri));
    Ok(conn)
}
