use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, AppSettings, Arg,
};
use failure::Error;
use log::*;
use pretty_env_logger;

use settings::Settings;
mod settings;

pub type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    pretty_env_logger::init();
    let matches = app_from_crate!()
        .setting(AppSettings::DeriveDisplayOrder)
        .arg(
            Arg::from_usage("-c --cfg [CFG_PATH] 'config file (toml) path'")
                .default_value("rog.toml"),
        )
        .arg(Arg::from_usage("<PATH> 'log path'").default_value("."))
        .get_matches();

    debug!("{:?}", &matches);

    let cfg = matches.value_of("cfg").unwrap();
    debug!("{:?}", &cfg);

    // Read config.
    let settings = Settings::new(cfg);

    debug!("{:?}", &settings);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_main() {
        assert_eq!(main().unwrap(), ());
    }

}
