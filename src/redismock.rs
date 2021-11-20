use std::{error::Error, pin::Pin};

use futures::{future, Future};

use crate::redisconn::DataProvider;

pub(crate) struct RedisMock {
    pub is_connected: bool,
}

impl DataProvider for RedisMock {
    fn check_connection<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(future::ready(self.is_connected))
    }

    fn set_int<'a>(
        &'a mut self,
        _key: String,
        _value: i64,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error + Send + Sync + 'static>>> + Send + 'a>>
    {
        Box::pin(future::ready(Ok(())))
    }
}

pub(crate) fn get_redis_mock() -> RedisMock {
    RedisMock { is_connected: true }
}
