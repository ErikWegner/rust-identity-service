use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crossbeam::channel::unbounded;
use crossbeam::channel::Sender;
use futures::future::Shared;
use futures::prelude::*;
use futures::Future;
use once_cell::sync::OnceCell;
use parking_lot::{Condvar, Mutex};
use serde::Serialize;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TokenData {
    pub token: String,
    pub expires: u64,
}

pub(crate) struct ClientCredentials {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
}

type AuthTokenFuture = Pin<Box<dyn Future<Output = TokenData> + Send>>;

trait AuthTokenFutureCallback {
    fn get_credentials(credentials: ClientCredentials) -> AuthTokenFuture
    where
        Self: Sized;
}

pub(crate) enum HolderState {
    Empty,
    RequestPending,
    HasToken { token: TokenData },
    HasTokenIsRefreshing { token: TokenData },
}

impl HolderState {
    fn get_token(&self) -> Option<TokenData> {
        match self {
            HolderState::Empty => Option::None,
            HolderState::RequestPending => Option::None,
            HolderState::HasToken { token } => Some(token.clone()),
            HolderState::HasTokenIsRefreshing { token } => Some(token.clone()),
        }
    }
}

async fn make_request_to_oidc_provider_dep(_key: String) -> TokenData {
    // Simulating a network request
    sleep(Duration::from_secs(2)).await;

    TokenData {
        token: String::from("mockdata"),
        expires: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30,
    }
}

pub(crate) fn make_request_to_oidc_provider(
    client_credentials: ClientCredentials,
) -> Pin<Box<dyn Future<Output = TokenData> + Send + Sync>> {
    let body = ureq::get(client_credentials.token_url.as_str())
        .call()
        .unwrap()
        .into_string()
        .unwrap();

    Box::pin(future::ready(TokenData {
        token: body,
        expires: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30,
    }))
}

fn request_mutex_dep() -> &'static tokio::sync::Mutex<Option<Shared<AuthTokenFuture>>> {
    static INSTANCE: OnceCell<tokio::sync::Mutex<Option<Shared<AuthTokenFuture>>>> =
        OnceCell::new();
    INSTANCE.get_or_init(|| tokio::sync::Mutex::new(Option::None))
}

pub(crate) fn request_mutex() -> Arc<(Mutex<HolderState>, Condvar)> {
    Arc::new((Mutex::new(HolderState::Empty), Condvar::new()))
}

pub(crate) fn get_auth_token_dep() -> AuthTokenFuture {
    Box::pin(async move {
        // Lock mutex to check for an existing result
        let mut result_exists_check = request_mutex_dep().lock().await;
        let fut = if result_exists_check.is_some() {
            result_exists_check.clone().unwrap()
        } else {
            // If no result is waiting, make a future and share it
            // for other request to wait for it.
            let request = make_request_to_oidc_provider_dep(String::new())
                .boxed()
                .shared();
            let _ = result_exists_check.insert(request.clone());

            request
        };

        // Release the lock to let other threads continue
        drop(result_exists_check);

        // await the future - it will retrieve token
        let result = fut.await;

        // Check result again
        let mut expire_check = request_mutex_dep().lock().await;
        let now_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if expire_check.is_none() {
            // Another thread has already realised the token has expired
            drop(expire_check);
            get_auth_token_dep().await
        } else if result.expires < now_seconds {
            // The latest result has expired, clear the value and retrieve a new one
            expire_check.take();
            drop(expire_check);
            get_auth_token_dep().await
        } else {
            // The lastest result is valid
            result
        }
    })
}

pub(crate) async fn get_auth_token(
    a: Arc<(Mutex<HolderState>, Condvar)>,
    tx: Sender<u8>,
) -> Result<TokenData, &'static str> {
    let &(ref lock, ref cvar) = &*a;
    let mut state = lock.lock();

    match &*state {
        HolderState::Empty => {
            println!("HolderState::Empty");
            // TODO: use valid credentials
            let _client_credentials = ClientCredentials {
                client_id: String::new(),
                client_secret: String::new(),
                token_url: String::new(),
            };
            let _r = tx.send(1);
            cvar.wait(&mut state);
            let token = state.get_token();
            return token.ok_or("Authentication failed");
        }
        HolderState::RequestPending {} => {
            println!("HolderState::RequestPending");
            cvar.wait(&mut state);
            let token = state.get_token();
            return token.ok_or("Authentication failed");
        }
        HolderState::HasToken { token } => {
            println!("HolderState::HasToken");
            let now_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if token.expires < now_seconds + 5 {
                let _r = tx.send(1);
            }
            return Ok(token.clone());
        }
        HolderState::HasTokenIsRefreshing { token } => return Ok(token.clone()),
    }

    // TODO: remove
    Err("It should never reach this point")
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

    use std::thread;

    use super::*;

    fn provide_token_and_notify(mutex: Arc<(Mutex<HolderState>, Condvar)>, token: TokenData) {
        let &(ref lock, ref cvar) = &*mutex;
        let mut state = lock.lock();
        *state = HolderState::HasToken { token };
        cvar.notify_all();
        drop(state);
    }

    fn set_state_to_empty(mutex: Arc<(Mutex<HolderState>, Condvar)>) {
        let &(ref lock, ref cvar) = &*mutex;
        let mut state = lock.lock();
        *state = HolderState::Empty;
        cvar.notify_all();
        drop(state);
    }

    fn set_state_to_request_pending(mutex: Arc<(Mutex<HolderState>, Condvar)>) {
        let &(ref lock, ref cvar) = &*mutex;
        let mut state = lock.lock();
        *state = HolderState::RequestPending;
        cvar.notify_all();
        drop(state);
    }

    fn set_state_to_has_token_is_refreshing(
        mutex: Arc<(Mutex<HolderState>, Condvar)>,
        token: TokenData,
    ) {
        let &(ref lock, ref cvar) = &*mutex;
        let mut state = lock.lock();
        *state = HolderState::HasTokenIsRefreshing { token };
        cvar.notify_all();
        drop(state);
    }

    #[test]
    fn state_change_from_empty_to_has_token() {
        // Arrange
        let state = request_mutex();
        let (s, t) = unbounded();
        let closure_state = state.clone();
        let closure_s = s;

        let th = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on(get_auth_token)");
            block_on(get_auth_token(closure_state, closure_s))
        });

        // Act
        let receive = t.recv_timeout(Duration::from_secs(2));
        provide_token_and_notify(
            state,
            TokenData {
                token: String::from("ABC"),
                expires: 43,
            },
        );

        // Assert
        let result = th.join().expect("No thread result");
        assert_eq!(result.unwrap().expires, 43);
        assert!(receive.is_ok());
    }

    #[test]
    fn state_change_from_empty_to_has_token_for_parallel_requests() {
        // Arrange
        let state = request_mutex();
        let (s, t) = unbounded();
        let closure1_state = state.clone();
        let closure2_state = state.clone();
        let closure1_s = s.clone();
        let closure2_s = s;

        let th1 = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on1");
            block_on(get_auth_token(closure1_state, closure1_s))
        });
        let th2 = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on2");
            block_on(get_auth_token(closure2_state, closure2_s))
        });

        let _receive_th1 = t.recv_timeout(Duration::from_secs(2));
        let _receive_th2 = t.recv_timeout(Duration::from_secs(2));

        // Act
        provide_token_and_notify(
            state,
            TokenData {
                token: String::from("ABC"),
                expires: 43,
            },
        );

        // Assert
        let result1 = th1.join().expect("No thread 1 result");
        let result2 = th2.join().expect("No thread 2 result");
        assert_eq!(result1.unwrap().expires, 43);
        assert_eq!(result2.unwrap().expires, 43);
    }

    #[test]
    fn state_change_from_pending_to_has_token() {
        // Arrange
        let state = request_mutex();
        let (s, t) = unbounded();
        let closure_state = state.clone();
        let closure_s = s;
        set_state_to_request_pending(state.clone());

        let th = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on(get_auth_token)");
            block_on(get_auth_token(closure_state, closure_s))
        });

        // Act
        let receive = t.recv_timeout(Duration::from_secs(2));
        provide_token_and_notify(
            state,
            TokenData {
                token: String::from("ABC"),
                expires: 237,
            },
        );

        // Assert
        let result = th.join().expect("No thread result");
        assert_eq!(result.unwrap().expires, 237);
        assert!(receive.is_err())
    }

    #[test]
    fn state_change_has_token_to_has_token_request_pending() {
        // Arrange
        let state = request_mutex();
        let (s, t) = unbounded();
        let closure_state = state.clone();
        let closure_s = s;
        let nearly_expired_token = TokenData {
            token: String::from("nearly_expired_token"),
            expires: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3,
        };
        provide_token_and_notify(state, nearly_expired_token);

        let th = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on(get_auth_token)");
            block_on(get_auth_token(closure_state, closure_s))
        });

        // Act
        let receive = t.recv_timeout(Duration::from_secs(2));

        // Assert
        let result = th.join().expect("No thread result");
        assert_eq!(result.unwrap().token, "nearly_expired_token");
        assert!(receive.is_ok());
    }

    #[test]
    fn provide_token_while_refreshing() {
        // Arrange
        let state = request_mutex();
        let (s, t) = unbounded();
        let closure_state = state.clone();
        let closure_s = s;
        let nearly_expired_token = TokenData {
            token: String::from("nearly_expired_token"),
            expires: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3,
        };
        set_state_to_has_token_is_refreshing(state.clone(), nearly_expired_token);

        let th = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on(get_auth_token)");
            block_on(get_auth_token(closure_state, closure_s))
        });

        // Act
        let receive = t.recv_timeout(Duration::from_secs(2));

        // Assert
        let result = th.join().expect("No thread result");
        assert_eq!(result.unwrap().token, "nearly_expired_token");
        assert!(receive.is_err());
    }

    #[test]
    fn can_reuse_condvar() {
        // Arrange
        let state = request_mutex();
        let (s, t) = unbounded();
        let closure1_state = state.clone();
        let closure2_state = state.clone();
        let closure1_s = s.clone();
        let closure2_s = s;
        let state1_clone = state.clone();
        let state2_clone = state.clone();

        let th = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on(get_auth_token)");
            block_on(get_auth_token(closure1_state, closure1_s))
        });

        let _receive = t.recv_timeout(Duration::from_secs(2));

        provide_token_and_notify(
            state1_clone,
            TokenData {
                token: String::from("ABC"),
                expires: 43,
            },
        );

        let result = th.join().expect("No thread result");
        assert_eq!(result.unwrap().expires, 43);

        set_state_to_empty(state2_clone);

        let th = thread::spawn(move || -> Result<TokenData, &str> {
            println!("block_on(get_auth_token)");
            block_on(get_auth_token(closure2_state, closure2_s))
        });

        let _receive = t.recv_timeout(Duration::from_secs(2));

        provide_token_and_notify(
            state,
            TokenData {
                token: String::from("ABC"),
                expires: 43,
            },
        );

        let result = th.join().expect("No thread result");
        assert_eq!(result.unwrap().expires, 43);
    }
}
