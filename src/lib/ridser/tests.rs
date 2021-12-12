use std::collections::BTreeMap;

use crate::{
    cfg::{
        RuntimeConfiguration, TokenConfiguration, TokenGeneratorConfiguration,
        TokenValidationConfiguration,
    },
    construct_redirect_uri, deserialize,
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

#[test]
fn it_constructs_redirect_uri() {
    // Arrange
    let rc = RuntimeConfiguration {
        authorization_endpoint: String::from(
            "https://my.server.com/auth/protocol/openid-connect/auth",
        ),
        token_url: String::new(),
        client_id: String::from("c44"),
        client_secret: String::from("s43"),
        redirect_uri: String::from("http://devserver.local:11280/callback"),
    };

    // Act
    let uri = construct_redirect_uri(&rc, "k8", "some6state1");

    // Assert
    assert_eq!(uri, "https://my.server.com/auth/protocol/openid-connect/auth?response_type=code&client_id=k8&redirect_uri=http%3A%2F%2Fdevserver.local%3A11280%2Fcallback&scope=openid&state=some6state1");
}
