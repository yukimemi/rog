use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Capture {
    Text(String),
    Csv(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rog {
    pub name: String,
    #[serde(rename = "match")]
    pub match_: String,
    pub capture: Capture,
    #[serde(default)]
    pub header_replace: bool,
    #[serde(default)]
    pub header_add: bool,
    pub parse: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Out {
    pub path: String,
    pub format: String,
    pub fields: Option<Vec<String>>,
    #[serde(default)]
    pub bom: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub debug: bool,
    pub rogs: Vec<Rog>,
    pub out: Option<Out>,
}

impl Settings {
    pub fn new<P: AsRef<Path>>(cfg: P) -> Result<Self, ConfigError> {
        let mut s = Config::new();

        // Start off by merging in the "default" configuration file
        s.merge(File::with_name(cfg.as_ref().to_str().unwrap()))?;

        // Add in a local configuration file
        // This file shouldn't be checked in to git
        s.merge(File::with_name("local").required(false))?;

        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        s.merge(Environment::with_prefix("app"))?;

        // Now that we're done, let's access our configuration
        // println!("debug: {:#?}", s.get_bool("debug"));

        // You can deserialize (and thus freeze) the entire configuration as
        s.try_into()
    }
}
