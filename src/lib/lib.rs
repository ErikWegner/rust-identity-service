use std::{env::{self}, error::Error};

use cfg::RuntimeConfiguration;
use serde::{Deserialize};

mod cfg;

pub mod ridser;

#[derive(Deserialize)]
struct OpenIdConfiguration {
    token_endpoint: String,
}

pub fn init_openid_provider() -> Result<RuntimeConfiguration, Box<dyn Error>> {
    let dicovery_endpoint = env::var("METADATA_URL")?;
    let body = ureq::get(&dicovery_endpoint).call()?.into_string()?;
    let des: OpenIdConfiguration = serde_json::from_str(&body)?;

    Ok(RuntimeConfiguration {
        token_url: des.token_endpoint,
    })
}
