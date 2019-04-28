use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
struct Rog {
    name: String,
    extension: String,
    path: Option<String>,
    capture: String,
}

#[derive(Debug, Deserialize)]
struct Out {
    path: String,
    format: String,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    debug: bool,
    rogs: Vec<Rog>,
    out: Option<Out>,
    fields: Option<Vec<String>>
}

impl Settings {
    pub fn new(cfg: &str) -> Result<Self, ConfigError> {
        let mut s = Config::new();

        // Start off by merging in the "default" configuration file
        s.merge(File::with_name(cfg))?;

        // Add in a local configuration file
        // This file shouldn't be checked in to git
        s.merge(File::with_name("config/local").required(false))?;

        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        s.merge(Environment::with_prefix("app"))?;

        // Now that we're done, let's access our configuration
        println!("debug: {:?}", s.get_bool("debug"));
        println!("database: {:?}", s.get::<String>("database.url"));

        // You can deserialize (and thus freeze) the entire configuration as
        s.try_into()
    }
}
