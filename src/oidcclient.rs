use std::marker::Send;
use std::pin::Pin;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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

type AuthTokenFuture = Pin<Box<dyn Future<Output = TokenData> + Send>>;

async fn make_request_to_oidc_provider(_key: String) -> TokenData {
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

fn request_mutex() -> &'static Mutex<Option<Shared<AuthTokenFuture>>> {
    static INSTANCE: OnceCell<Mutex<Option<Shared<AuthTokenFuture>>>> = OnceCell::new();
    INSTANCE.get_or_init(|| Mutex::new(Option::None))
}

pub(crate) fn get_auth_token() -> AuthTokenFuture {
    Box::pin(async move {
        // Lock mutex to check for an existing result
        let mut result_exists_check = request_mutex().lock().await;
        let fut = if result_exists_check.is_some() {
            result_exists_check.clone().unwrap()
        } else {
            // If no result is waiting, make a future and share it
            // for other request to wait for it.
            let request = make_request_to_oidc_provider(String::new())
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
        let mut expire_check = request_mutex().lock().await;
        let now_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if expire_check.is_none() {
            // Another thread has already realised the token has expired
            drop(expire_check);
            get_auth_token().await
        } else if result.expires < now_seconds {
            // The latest result has expired, clear the value and retrieve a new one
            expire_check.take();
            drop(expire_check);
            get_auth_token().await
        } else {
            // The lastest result is valid
            result
        }
    })
}
