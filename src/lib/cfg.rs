#[derive()]
pub struct TokenConfiguration {
    pub key: String,
}

pub struct TokenGeneratorConfiguration {
    pub common: TokenConfiguration,
    pub iss: String,
}

pub struct TokenValidationConfiguration {
    pub common: TokenConfiguration,
}

#[derive(Clone)]
pub struct RuntimeConfiguration {
    pub token_url: String,
    pub authorization_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}
