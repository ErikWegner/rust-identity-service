use cfg::RuntimeConfiguration;

mod cfg;

pub mod ridser;

pub fn init_openid_provider() -> RuntimeConfiguration {
    RuntimeConfiguration {
        token_url: String::from(""),
    }
}
