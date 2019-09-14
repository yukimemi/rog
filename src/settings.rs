use chrono::offset::TimeZone;
use chrono::{DateTime, Duration, Local};
use config::{Config, ConfigError, Environment, File};
use serde::{self, Deserialize, Deserializer};
use serde_derive::Deserialize;
use std::collections::HashMap;
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
    pub parse: Vec<String>,
    #[serde(default)]
    #[serde(deserialize_with = "time_duration")]
    pub add_time: Option<Duration>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Out {
    pub path: String,
    pub format: String,
    pub fields: Vec<String>,
    #[serde(default)]
    pub bom: bool,
    pub grep: Option<Vec<HashMap<String, String>>>,
    pub grep_path: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "time_default")]
    pub start: Option<DateTime<Local>>,
    #[serde(default)]
    #[serde(deserialize_with = "time_default")]
    pub end: Option<DateTime<Local>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub debug: bool,
    pub rogs: Vec<Rog>,
    pub out: Option<Out>,
}

fn time_default<'de, D>(d: D) -> Result<Option<DateTime<Local>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    if &s == "" {
        Ok(None)
    } else if let Ok(time) = Local.datetime_from_str(&s, "%Y%m%d") {
        Ok(Some(time))
    } else {
        Local
            .datetime_from_str(&s, "%Y%m%d%H%M%S")
            .map_err(serde::de::Error::custom)
            .map(|d| Some(d))
    }
}
fn time_duration<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let num = i64::deserialize(d)?;
    let dur = Duration::nanoseconds(num);
    Ok(Some(dur))
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
