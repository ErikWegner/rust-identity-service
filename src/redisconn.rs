use std::{env, error::Error};

use redis::{Commands, ConnectionLike};

pub trait DataProvider: Send {
    fn check_connection(&mut self) -> bool;
    fn set_int(&mut self, key: String, value: i64) -> Result<(), Box<dyn Error>>;
}

pub struct RealRedis {
    conn: redis::Connection,
}

impl DataProvider for RealRedis {
    fn check_connection(&mut self) -> bool {
        self.conn.check_connection()
    }

    fn set_int(&mut self, key: String, value: i64) -> Result<(), Box<dyn Error>> {
        if let Err(err) = self.conn.set::<String, i64, bool>(key, value) {
            Err(Box::new(err))
        } else {
            Ok(())
        }
    }
}

pub fn get_redis_connection() -> Result<RealRedis, Box<dyn Error>> {
    let redis_uri = env::var("RIDSER_REDIS_URI").expect("Value for RIDSER_REDIS_URI is not set.");
    let client = redis::Client::open(redis_uri.as_str())
        .unwrap_or_else(|_| panic!("Uri {} invalid.", redis_uri));
    let conn = client
        .get_connection()
        .unwrap_or_else(|_| panic!("Connection to {} failed.", redis_uri));
    Ok(RealRedis { conn })
}
