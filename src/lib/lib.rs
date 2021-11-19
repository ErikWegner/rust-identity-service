use std::{
    env::{self},
    error::Error,
};

use cfg::RuntimeConfiguration;
use serde::Deserialize;

pub mod cfg;

pub mod ridser;

#[derive(Deserialize)]
struct OpenIdConfiguration {
    authorization_endpoint: String,
    token_endpoint: String,
}

fn deserialize(body: String) -> Result<OpenIdConfiguration, Box<dyn Error>> {
    let o: OpenIdConfiguration = serde_json::from_str(&body)?;
    Ok(o)
}

pub fn init_openid_provider() -> Result<RuntimeConfiguration, Box<dyn Error>> {
    let dicovery_endpoint = env::var("RIDSER_METADATA_URL").expect("Value for RIDSER_METADATA_URL is not set.");
    let body = ureq::get(&dicovery_endpoint).call()?.into_string()?;
    let des = deserialize(body)?;

    Ok(RuntimeConfiguration {
        authorization_endpoint: des.authorization_endpoint,
        token_url: des.token_endpoint,
        client_id: env::var("RIDSER_CLIENT_ID").expect("Value for RIDSER_CLIENT_ID is not set."),
        redirect_uri: env::var("RIDSER_REDIRECT_URI").expect("Value for RIDSER_REDIRECT_URI is not set."),
    })
}

pub fn construct_redirect_uri(rc: &RuntimeConfiguration, client_id: &str, state: &str) -> String {
    String::from(
        url::Url::parse_with_params(
            &(rc.authorization_endpoint),
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", &(rc.redirect_uri)),
                ("scope", "openid"),
                ("state", state),
            ],
        )
        .unwrap()
        .as_str(),
    )
}
