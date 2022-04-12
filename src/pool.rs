// HQ: Erzeugt MPSC GibMirArbeit

// Alle Worker senden ein OneShot via GibMirArbeit

// HQ: Wartet auf Aufruf mit AufruferAntwortKanal
// HQ: Wartet auf GibMirArbeit
// HQ: Gibt AufruferAntwortKanal via GibMirArbeit-OneShot-Response zurück

use tokio::{
    sync::{
        mpsc::{self, UnboundedSender},
        oneshot,
    },
    task,
};

struct PoolWorker1 {
    index: usize,
}

impl PoolWorker1 {
    fn new(index: usize) -> Self {
        PoolWorker1 { index }
    }

    fn spawn(&self, hqo: mpsc::UnboundedSender<PoolWorkerQueue>) -> tokio::task::JoinHandle<()> {
        let hq = hqo.clone();
        let windex = self.index;
        tokio::spawn(async move {
            let mut keeprunning = true;
            while keeprunning {
                println!("worker: keeprunning");
                let (task_tx, mut task_rx) = oneshot::channel::<PoolTask>();
                println!("worker -> hq");
                let _ = hq.send(PoolWorkerQueue { task: task_tx });
                let mut waitforhq = true;
                while waitforhq {
                    let waitresult = task_rx.try_recv();
                    match waitresult {
                        Ok(task) => {
                            println!("worker: got task");
                            waitforhq = false;
                            let _ = task
                                .response
                                .send(format!("Response from worker #{}: {}", windex, task.arg));
                        }
                        Err(errkind) => match errkind {
                            oneshot::error::TryRecvError::Empty => {
                                task::yield_now().await;
                            }
                            oneshot::error::TryRecvError::Closed => {
                                keeprunning = false;
                                waitforhq = false;
                            }
                        },
                    }
                }
            }
            println!("worker: shutdown");
        })
    }
}

struct PoolWorkerQueue {
    task: oneshot::Sender<PoolTask>,
}

struct PoolTask {
    arg: String,
    response: oneshot::Sender<String>,
}

pub(crate) struct PoolHQ {
    client_requests_tx: UnboundedSender<PoolTask>,
}

impl PoolHQ {
    pub(crate) fn new(count: usize) -> Self {
        let (workers_tx, mut workers_rx) = mpsc::unbounded_channel::<PoolWorkerQueue>();
        let (client_requests_tx, mut client_requests_rx) = mpsc::unbounded_channel::<PoolTask>();

        for worker_index in 1..count {
            let worker = PoolWorker1::new(worker_index);
            worker.spawn(workers_tx.clone());
        }
        tokio::spawn(async move {
            loop {
                let client_request_result = client_requests_rx.try_recv();
                if let Ok(client_request) = client_request_result {
                    let worker = workers_rx.recv().await;
                    println!("hq has worker recv");
                    if let Some(nextworker) = worker {
                        println!("hq -> worker");
                        let _ = nextworker.task.send(client_request);
                    } else {
                        return;
                    }
                }
            }
        });

        PoolHQ { client_requests_tx }
    }

    pub(crate) async fn handle(&self, arg: String) -> Option<String> {
        let (response_tx, mut response_rx) = oneshot::channel::<String>();

        let send_task_result = self.client_requests_tx.send(PoolTask {
            arg,
            response: response_tx,
        });
        if send_task_result.is_err() {
            return None;
        }

        let mut wait_cycles = 10;
        while wait_cycles > 0 {
            wait_cycles = wait_cycles - 1;
            let receive_result = response_rx.try_recv();
            match receive_result {
                Ok(response) => return Some(response),
                Err(err_kind) => match err_kind {
                    oneshot::error::TryRecvError::Empty => {
                        println!("empty");
                        task::yield_now().await;
                    }
                    oneshot::error::TryRecvError::Closed => {}
                },
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::{
        sync::{
            mpsc,
            oneshot::{self, error::TryRecvError},
        },
        time::sleep,
    };

    use super::{PoolHQ, PoolTask, PoolWorker1, PoolWorkerQueue};

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
                let (rx, mut tx) = oneshot::channel::<String>();
                let t = PoolTask {
                    arg: String::from("zork"),
                    response: rx,
                };
                let e = q.task.send(t);
                if e.is_err() {
                    panic!("Cannot send");
                }
                let mut waiter = 3;
                while waiter > 0 {
                    let result = tx.try_recv();
                    match result {
                        Ok(text) => assert_eq!("Response from worker #3: zork", text),
                        Err(k) => match k {
                            TryRecvError::Empty => {
                                if waiter > 0 {
                                    waiter = waiter - 1;
                                    sleep(Duration::from_millis(100)).await;
                                } else {
                                    panic!("Empty");
                                }
                            }
                            TryRecvError::Closed => panic!("Closed"),
                        },
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
