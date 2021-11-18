use std::error::Error;

use crate::redisconn::DataProvider;

struct RedisMock;

impl DataProvider for RedisMock {
    fn check_connection(&mut self) -> bool {
        true
    }

    fn set_int(&mut self, key: String, value: i64) -> Result<(), Box<dyn Error>> {
            Ok(())
        
    }
}

pub(crate) fn get_redis_mock() -> impl DataProvider {
    RedisMock{}
}
