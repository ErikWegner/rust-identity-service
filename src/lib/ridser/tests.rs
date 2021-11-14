use std::collections::BTreeMap;

use crate::{
    cfg::{TokenConfiguration, TokenGeneratorConfiguration, TokenValidationConfiguration},
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
