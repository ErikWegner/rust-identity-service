use hmac::{Hmac, NewMac};
use jwt::{SignWithKey, VerifyWithKey};
use sha2::Sha256;
use std::collections::BTreeMap;

use crate::cfg::{RuntimeConfiguration, TokenGeneratorConfiguration, TokenValidationConfiguration};

pub fn create_token_string(c: TokenGeneratorConfiguration, subject: &str) -> String {
    let key: Hmac<Sha256> = Hmac::new_from_slice(c.common.key.as_bytes()).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("iss", c.iss.as_str());
    claims.insert("sub", subject);

    claims.sign_with_key(&key).unwrap()
}

pub fn validate_extract(
    token_str: String,
    c: TokenValidationConfiguration,
) -> BTreeMap<String, String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(c.common.key.as_bytes()).unwrap();
    let claims: BTreeMap<String, String> = token_str.verify_with_key(&key).unwrap();
    claims
}

#[cfg(test)]
mod tests;
