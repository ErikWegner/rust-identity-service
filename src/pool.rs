// HQ: Erzeugt MPSC GibMirArbeit

// Alle Worker senden ein OneShot via GibMirArbeit

// HQ: Wartet auf Aufruf mit AufruferAntwortKanal
// HQ: Wartet auf GibMirArbeit
// HQ: Gibt AufruferAntwortKanal via GibMirArbeit-OneShot-Response zurück

use tokio::sync::mpsc::{channel, unbounded_channel, Sender, UnboundedSender};

struct PoolWorker1 {
    index: usize,
}

impl PoolWorker1 {
    fn new(index: usize) -> Self {
        PoolWorker1 { index }
    }

    fn spawn(&self, hqo: UnboundedSender<PoolWorkerQueue>) -> tokio::task::JoinHandle<()> {
        let hq = hqo.clone();
        let windex = self.index;
        tokio::spawn(async move {
            let mut keeprunning = true;
            while keeprunning {
                println!("worker: keeprunning");
                let (task_tx, mut task_rx) = channel::<PoolTask>(1);
                println!("worker -> hq");
                let _ = hq.send(PoolWorkerQueue { task: task_tx });
                let mut waitforhq = true;
                while waitforhq {
                    let waitresult = task_rx.recv().await;
                    match waitresult {
                        Some(task) => {
                            println!("worker: got task");
                            waitforhq = false;
                            let _ = task
                                .response
                                .send(format!("Response from worker #{}: {}", windex, task.arg))
                                .await;
                        }
                        None => {
                            waitforhq = false;
                            keeprunning = false;
                        }
                    }
                }
            }
            println!("worker: shutdown");
        })
    }
}

struct PoolWorkerQueue {
    task: Sender<PoolTask>,
}

struct PoolTask {
    arg: String,
    response: Sender<String>,
}

pub(crate) struct PoolHQ {
    client_requests_tx: UnboundedSender<PoolTask>,
}

impl PoolHQ {
    pub(crate) fn new(count: usize) -> Self {
        let (workers_tx, mut workers_rx) = unbounded_channel::<PoolWorkerQueue>();
        let (client_requests_tx, mut client_requests_rx) = unbounded_channel::<PoolTask>();

        for worker_index in 1..count {
            let worker = PoolWorker1::new(worker_index);
            worker.spawn(workers_tx.clone());
        }
        tokio::spawn(async move {
            loop {
                let client_request_result = client_requests_rx.recv().await;
                if let Some(client_request) = client_request_result {
                    let worker = workers_rx.recv().await;
                    println!("hq has worker recv");
                    if let Some(nextworker) = worker {
                        println!("hq -> worker");
                        let _ = nextworker.task.send(client_request).await;
                    } else {
                        return;
                    }
                }
            }
        });

        PoolHQ { client_requests_tx }
    }

    pub(crate) async fn handle(&self, arg: String) -> Option<String> {
        let (response_tx, mut response_rx) = channel::<String>(1);

        let send_task_result = self.client_requests_tx.send(PoolTask {
            arg,
            response: response_tx,
        });
        if send_task_result.is_err() {
            return None;
        }

        return response_rx.recv().await;
    }
}

#[cfg(test)]
mod test {
    use tokio::sync::mpsc::{self, channel};

    use super::{PoolTask, PoolWorker1, PoolWorkerQueue};

    #[tokio::test]
    async fn test_early_close() {
        let w1 = PoolWorker1::new(3);
        let (give_me_work_tx, give_me_work_rx) = mpsc::unbounded_channel::<PoolWorkerQueue>();
        let w1handle = w1.spawn(give_me_work_tx);

        drop(give_me_work_rx);
        let r = tokio::try_join!(w1handle);
        if let Err(err) = r {
            panic!("{}", err);
        }
    }

    #[tokio::test]
    async fn test_worker_response1() {
        let w1 = PoolWorker1::new(3);
        let (give_me_work_tx, mut give_me_work_rx) = mpsc::unbounded_channel::<PoolWorkerQueue>();
        let w1handle = w1.spawn(give_me_work_tx);

        let taskresult = give_me_work_rx.recv().await;
        match taskresult {
            Some(q) => {
                let (rx, mut tx) = channel::<String>(1);
                let t = PoolTask {
                    arg: String::from("zork"),
                    response: rx,
                };
                let e = q.task.send(t).await;
                if e.is_err() {
                    panic!("Cannot send");
                }
                let result = tx.recv().await;
                match result {
                    Some(text) => {
                        assert_eq!("Response from worker #3: zork", text);
                    }
                    None => {
                        panic!("Empty")
                    }
                }
            }
            _ => {
                panic!("Failed to receive");
            }
        }

        drop(give_me_work_rx);
        let r = tokio::try_join!(w1handle);
        if let Err(err) = r {
            panic!("{}", err);
        }
    }
}
