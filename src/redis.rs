use std::sync::Arc;

use parking_lot::Mutex;

#[cfg(test)]
#[path = "./redis_tests.rs"]
mod redis_tests;

pub(crate) struct Redis {
    cache_seconds: usize,
    client: Arc<Mutex<simple_redis::client::Client>>,
}

impl Redis {
    pub fn new() -> Self {
        // TODO: configurable connection
        let client1 = simple_redis::create("redis://redis/");
        let client2 = client1.expect("Redis connection failed");
        Self {
            cache_seconds: 10 * 60,
            client: Arc::new(Mutex::new(client2)),
        }
    }

    pub async fn set_cache_result(&self, subject: &str, groups: &[String]) {
        let key = subject_key(subject);
        let value = groups.join(",");
        let mut rediscon = self.client.lock();
        let _ = rediscon.setex(key.as_str(), value.as_str(), self.cache_seconds);
    }

    pub async fn get_cache_result(&self, subject: &str) -> Option<Vec<String>> {
        let key = subject_key(subject);
        let mut rediscon = self.client.lock();
        let r = rediscon.get_string(key.as_str());
        drop(rediscon);
        if let Ok(s) = r {
            let list_of_groups = s.split(',').map(String::from).collect::<Vec<String>>();
            Some(list_of_groups)
        } else {
            None
        }
    }
}

fn subject_key(subject: &str) -> String {
    format!("subject-{}", subject)
}
