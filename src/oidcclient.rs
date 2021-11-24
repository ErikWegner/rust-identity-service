use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use futures::executor::block_on;
use futures::future::Shared;
use futures::prelude::*;
use futures::Future;
use once_cell::sync::OnceCell;
use serde::Serialize;
use tokio::{
    sync::Mutex,
    time::{sleep, Duration},
};

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

pub(crate) enum HolderState<'a> {
    Empty,
    RequestPending {
        request: Shared<Pin<Box<dyn Future<Output = TokenData> + Send + 'a>>>,
    },
    HasToken {
        token: TokenData,
    },
    HasTokenIsRefreshing {
        request: Shared<Pin<Box<dyn Future<Output = TokenData> + Send>>>,
        token: TokenData,
    },
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

fn request_mutex_dep() -> &'static Mutex<Option<Shared<AuthTokenFuture>>> {
    static INSTANCE: OnceCell<Mutex<Option<Shared<AuthTokenFuture>>>> = OnceCell::new();
    INSTANCE.get_or_init(|| Mutex::new(Option::None))
}

pub(crate) fn request_mutex() -> &'static Mutex<Option<HolderState<'static>>> {
    static INSTANCE: OnceCell<Mutex<Option<HolderState>>> = OnceCell::new();
    INSTANCE.get_or_init(|| Mutex::new(Option::Some(HolderState::Empty)))
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

pub(crate) async fn get_auth_token<'a, F>(
    state: &Mutex<Option<HolderState<'a>>>,
    credential_provider: &dyn Fn(ClientCredentials) -> F,
) -> TokenData
where
    F: Future<Output = TokenData> + Sync + Send + 'a,
{
    let mut result_exists_check = state.lock().await;
    let r1 = result_exists_check.as_ref().unwrap();
    match r1 {
        HolderState::Empty => {
            // TODO: use valid credentials
            let client_credentials = ClientCredentials {
                client_id: String::new(),
                client_secret: String::new(),
                token_url: String::new(),
            };
            let b = credential_provider(client_credentials).boxed();
            let _ = result_exists_check.insert(HolderState::RequestPending {
                request: b.shared(),
            });
        }
        HolderState::RequestPending { request } => {}
        HolderState::HasToken { token } => {}
        HolderState::HasTokenIsRefreshing { request, token } => {}
    }

    // TODO: remove
    TokenData {
        expires: 0,
        token: String::new(),
    }
}

#[cfg(test)]
fn mock_request_to_oidc_provider<'a>(
    delay_seconds: u16,
    token_data: TokenData,
) -> Box<dyn Fn(ClientCredentials) -> Pin<Box<dyn Future<Output = TokenData> + Sync + Send + 'a>>> {
    use std::thread;

    Box::new(move |_credentials| {
        // Simulating a network request
        thread::sleep(Duration::from_secs(delay_seconds.into()));

        Box::pin(future::ready(token_data.clone()))
    })
}

#[test]
fn state_change_from_empty_to_request_pending() {
    // Arrange
    let state = Mutex::new(Option::Some(HolderState::Empty));
    let callback = mock_request_to_oidc_provider(
        2,
        TokenData {
            token: String::from("mockdata"),
            expires: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 30,
        },
    );
    let fut = get_auth_token(&state, &callback);
    let client_credentials = ClientCredentials {
        client_id: String::new(),
        client_secret: String::new(),
        token_url: String::new(),
    };

    // Act
    let result = block_on(fut);

    // Assert
    assert_eq!(result.expires, 0);
    let guard = block_on(state.lock());
    assert_eq!(
        std::mem::discriminant(guard.as_ref().unwrap()),
        std::mem::discriminant(&HolderState::RequestPending {
            request: Shared::boxed(callback(client_credentials).shared()).shared()
        })
    );
}

#[test]
fn state_change_from_request_pending_to_has_token() {
    // Arrange
    let state = Mutex::new(Option::Some(HolderState::Empty));
    let callback = mock_request_to_oidc_provider(
        0,
        TokenData {
            token: String::from("mockdata"),
            expires: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 30,
        },
    );
    let fut = get_auth_token(&state, &callback);
    let client_credentials = ClientCredentials {
        client_id: String::new(),
        client_secret: String::new(),
        token_url: String::new(),
    };

    // Act
    let result = block_on(fut);

    // Assert
    assert_eq!(result.expires, 0);
    let guard = block_on(state.lock());
    assert_eq!(
        std::mem::discriminant(guard.as_ref().unwrap()),
        std::mem::discriminant(&HolderState::HasToken {
            token: TokenData {
                token: String::new(),
                expires: 0
            }
        })
    );
}
