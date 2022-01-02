use std::sync::mpsc::{channel, Sender};

use tokio::sync::{mpsc::unbounded_channel, oneshot};
use tokio::task;

#[cfg(test)]
#[path = "./redis_tests.rs"]
mod redis_tests;

enum RedisDirection {
    Read,
    Write,
}

struct RedisGroupRWTask {
    subject: String,
    direction: RedisDirection,
    groups: Option<Vec<String>>,
    tx: oneshot::Sender<Option<Vec<String>>>,
}

pub(crate) struct Redis {
    taskqueue: tokio::sync::mpsc::UnboundedSender<RedisGroupRWTask>,
}

impl Redis {
    pub fn new(connection_string: &str) -> Self {
        // crossbeam_deque -> erzeuge eine FIFO-Schlage https://docs.rs/crossbeam-deque/0.8.1/crossbeam_deque/struct.Worker.html#examples
        /* Erzeuge Task: https://docs.rs/tokio/latest/tokio/task/index.html#spawn_blocking */
        /* Erzeuge MPSC-Channel, Empfänger ist im Task, Sender bleibt hier. Sammle alle Sender in einer Liste */
        /* AtomicInteger: index auf den Sender-Listenindex, der als nächstes den Auftrag erhält */

        let capacity = 5; // TODO: dynamic
        let cache_seconds = 10 * 60; // TODO: dynamic
        let mut workers = Vec::<Sender<RedisGroupRWTask>>::with_capacity(capacity);
        for _worker_index in 0..capacity - 1 {
            let (ws1, wr1) = channel::<RedisGroupRWTask>();
            workers.push(ws1);
            let connection_string = connection_string.to_string();
            task::spawn_blocking(move || {
                let client1 = simple_redis::create(connection_string.as_str());
                let mut client2 = client1.expect("Redis connection failed");

                while let Ok(task) = wr1.recv() {
                    let key = subject_groups_key(task.subject.as_str());
                    let response = match task.direction {
                        RedisDirection::Read => {
                            let r = client2.get_string(key.as_str());
                            if let Ok(s) = r {
                                let list_of_groups =
                                    s.split(',').map(String::from).collect::<Vec<String>>();
                                Some(list_of_groups)
                            } else {
                                None
                            }
                        }
                        RedisDirection::Write => {
                            let value = task.groups.as_ref().unwrap().join(",");
                            let _ = client2.setex(key.as_str(), value.as_str(), cache_seconds);
                            task.groups
                        }
                    };
                    let _ = task.tx.send(response);
                }
            });
        }

        let (s1, mut r1) = unbounded_channel::<RedisGroupRWTask>();

        task::spawn(async move {
            let mut worker_index = 0;
            while let Some(task) = r1.recv().await {
                if let Err(e) = workers.get(worker_index).unwrap().send(task) {
                    println!("Comm1Error {}", e);
                }
                worker_index = (worker_index + 1) % capacity;
            }
        });

        Self { taskqueue: s1 }
    }

    pub async fn set_cache_result(&self, subject: &str, groups: &[String]) {
        let (tx, rx) = oneshot::channel::<Option<Vec<String>>>();
        let task = RedisGroupRWTask {
            subject: subject.to_string(),
            direction: RedisDirection::Write,
            groups: Some(groups.to_vec()),
            tx,
        };
        let _ = self.taskqueue.send(task);
        let _ = rx.await.unwrap();
    }

    pub async fn get_cache_result(&self, subject: &str) -> Option<Vec<String>> {
        let (tx, rx) = oneshot::channel::<Option<Vec<String>>>();
        let task = RedisGroupRWTask {
            subject: subject.to_string(),
            direction: RedisDirection::Read,
            groups: None,
            tx,
        };
        let _ = self.taskqueue.send(task);
        rx.await.unwrap()
    }
}

fn subject_groups_key(subject: &str) -> String {
    format!("subject/{}/groups", subject)
}
