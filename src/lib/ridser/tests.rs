use std::collections::BTreeMap;

use crate::{
    cfg::{TokenConfiguration, TokenGeneratorConfiguration, TokenValidationConfiguration},
    deserialize,
    ridser::{create_token_string, validate_extract},
};

fn assert_claim(claims: &BTreeMap<String, String>, claim_name: &str, claim_value: &str) {
    assert!(claims.contains_key(claim_name));
    assert_eq!(claims[claim_name], claim_value);
}

#[test]
fn it_works() {
    // Arrange
    let subject = "f83dlf9";
    let issuer = "http://ridser.authorization.example";
    let key = String::from("some secret text");
    let generator_config = TokenGeneratorConfiguration {
        common: TokenConfiguration { key: key.clone() },
        iss: issuer.into(),
    };
    let validator_config = TokenValidationConfiguration {
        common: TokenConfiguration { key },
    };

    // Act
    let token_str = create_token_string(generator_config, subject);

    // Assert
    let claims = validate_extract(token_str, validator_config);
    assert_claim(&claims, "iss", issuer);
    assert_claim(&claims, "sub", subject);
}

#[test]
fn it_converts_body_to_object() {
    // Arrange
    let body = String::from(concat!(
        "{",
        "\"authorization_endpoint\":\"https://my.server.com/auth/protocol/openid-connect/auth\",",
        "\"token_endpoint\":\"https://my.server.com/auth/protocol/openid-connect/token\"",
        "}"
    ));

    // Act
    let result = deserialize(body).unwrap();

    // Assert
    assert_eq!(
        result.token_endpoint,
        "https://my.server.com/auth/protocol/openid-connect/token"
    );
    assert_eq!(
        result.authorization_endpoint,
        "https://my.server.com/auth/protocol/openid-connect/auth"
    );
}
