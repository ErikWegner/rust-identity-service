use std::{env::{self}, error::Error};

use cfg::RuntimeConfiguration;
use serde::{Deserialize};

mod cfg;

pub mod ridser;

#[derive(Deserialize)]
struct OpenIdConfiguration {
    authorization_endpoint: String,
    token_endpoint: String,
}

fn deserialize(body: String) -> Result<OpenIdConfiguration, Box<dyn Error>> {
    let o : OpenIdConfiguration = serde_json::from_str(&body)?;
    Ok(o)
}

pub fn init_openid_provider() -> Result<RuntimeConfiguration, Box<dyn Error>> {
    let dicovery_endpoint = env::var("METADATA_URL")?;
    let body = ureq::get(&dicovery_endpoint).call()?.into_string()?;
    let des= deserialize(body)?;

    Ok(RuntimeConfiguration {
        authorization_endpoint: des.authorization_endpoint,
        token_url: des.token_endpoint,
    })
}
