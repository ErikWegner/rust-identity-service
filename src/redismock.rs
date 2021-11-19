use std::error::Error;

use crate::redisconn::DataProvider;

pub(crate) struct RedisMock {
    pub is_connected: bool,
}

impl DataProvider for RedisMock {
    fn check_connection(&mut self) -> bool {
        self.is_connected
    }

    fn set_int(&mut self, key: String, value: i64) -> Result<(), Box<dyn Error>> {
            Ok(())
        
    }
}

pub(crate) fn get_redis_mock() -> RedisMock {
    RedisMock{is_connected : true}
}
