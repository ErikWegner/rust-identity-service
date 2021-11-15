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

pub struct RuntimeConfiguration {
    pub token_url: String,
}