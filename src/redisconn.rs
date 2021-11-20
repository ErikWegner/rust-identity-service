use std::{env, error::Error, future::Future, pin::Pin};

use redis::aio::ConnectionManager;

pub trait DataProvider: Send {
    fn check_connection<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
    fn set_int<'a>(
        &'a mut self,
        key: String,
        value: i64,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), Box<dyn Error + Send + Sync + 'static>>>
                + Send
                + 'a,
        >,
    >;
}

pub struct RealRedis {
    conn: ConnectionManager,
}

impl DataProvider for RealRedis {
    fn check_connection<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        async fn ping(r: &'_ mut RealRedis) -> bool {
            redis::cmd("PING")
                .query_async::<ConnectionManager, String>(&mut r.conn)
                .await
                .is_ok()
        }

        Box::pin(ping(self))
    }

    fn set_int<'a>(
        &'a mut self,
        key: String,
        value: i64,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), Box<dyn Error + Send + Sync + 'static>>>
                + Send
                + 'a,
        >,
    > {
        async fn set(
            r: &'_ mut RealRedis,
        ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
            if let Err(err) = redis::cmd("SET")
                .query_async::<ConnectionManager, ()>(&mut r.conn)
                .await
            {
                Err(Box::new(err))
            } else {
                Ok(())
            }
        }
        Box::pin(set(self))
    }
}

pub async fn get_redis_connection() -> Result<RealRedis, Box<dyn Error>> {
    let redis_uri = env::var("RIDSER_REDIS_URI").expect("Value for RIDSER_REDIS_URI is not set.");
    let client = redis::Client::open(redis_uri.as_str())
        .unwrap_or_else(|_| panic!("Uri {} invalid.", redis_uri));
    let conn = client
        .get_tokio_connection_manager()
        .await
        .expect("Redis connection manager unavailable");
    Ok(RealRedis { conn })
}
