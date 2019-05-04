use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, AppSettings, Arg,
};
use csv;
use failure::Error;
use log::*;
use pretty_env_logger;
use regex::Regex;
use settings::{Capture, Settings};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use walkdir::{DirEntry, WalkDir};

mod settings;

type Result<T> = std::result::Result<T, Error>;
type Line = HashMap<String, String>;

#[derive(Debug, Clone)]
struct Rog {
    name: String,
    path: PathBuf,
    capture: Capture,
    lines: Vec<Line>,
}

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

    let cfg = matches.value_of("cfg").unwrap();

    // Read config.
    let settings = Settings::new(cfg)?;

    debug!("{:#?}", &settings);

    // Get logs.
    let input = matches.value_of("PATH").unwrap();
    let recv = get_entries(input);

    // Filter logs.
    let rogs = recv
        .iter()
        .filter_map(|de| get_rog(de.path(), &settings))
        .collect::<Vec<_>>();

    // Parse lines of rogs.
    rogs.iter().map(|rog| rog.parse_lines()).collect::<Vec<_>>();

    Ok(())
}

impl Rog {
    fn new<P: AsRef<Path>>(name: String, path: P, capture: &Capture) -> Rog {
        Rog {
            name: name,
            path: Path::new(path.as_ref()).to_path_buf(),
            capture: capture.clone(),
            lines: vec![],
        }
    }

    fn parse_lines(&self) -> Result<Self> {
        match &self.capture {
            Capture::Text(cap) => self.parse_with_text(cap.clone()),
            Capture::Csv(cap) => self.parse_with_csv(cap.clone()),
        }
    }

    fn parse_with_csv(&self, cap: HashMap<String, usize>) -> Result<Self> {
        // Open rog.
        let f = fs::File::open(&self.path)?;
        let mut rdr = csv::Reader::from_reader(f);
        let mut lines: Vec<Line> = Vec::new();
        rdr.records().for_each(|r| match r {
            Ok(r) => {
                // debug!("{:#?}", r);
                let mut line = HashMap::new();
                cap.iter().for_each(|(k, v)| {
                    match r.get(*v) {
                        Some(col) => {
                            line.insert(k.to_string(), col.to_string());
                        }
                        None => eprintln!("{:#?} has not {} column !", r, v),
                    };
                });
                lines.push(line);
            }
            Err(e) => eprintln!("{}", e),
        });

        // debug!("{:#?}", lines);

        Ok(Rog {
            lines: lines,
            ..self.clone()
        })
    }
    fn parse_with_text(&self, cap: String) -> Result<Self> {
        Ok(Rog { ..self.clone() })
    }
}

fn get_rog<P: AsRef<Path>>(path: P, cfg: &Settings) -> Option<Rog> {
    cfg.rogs.iter().find_map(|rog| {
        let re = Regex::new(&rog.match_).unwrap();
        match re.is_match(path.as_ref().to_str().unwrap()) {
            true => Some(Rog::new(rog.name.to_string(), &path, &rog.capture)),
            false => None,
        }
    })
}

fn get_entries<P: AsRef<Path>>(path: P) -> mpsc::Receiver<DirEntry> {
    let (tx, rx) = mpsc::channel();
    let path = path.as_ref().to_path_buf();
    thread::spawn(move || {
        WalkDir::new(path).into_iter().for_each(|e| match e {
            Ok(e) => {
                if !e.file_type().is_dir() {
                    tx.send(e).unwrap()
                }
            }
            Err(e) => eprintln!("{}", e),
        });
        drop(tx);
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn get_test_rogs() -> mpsc::Receiver<DirEntry> {
        let mut cwd = env::current_dir().unwrap();
        cwd.push("test");
        get_entries(cwd)
    }

    #[test]
    fn test_main() {
        assert_eq!(main().unwrap(), ());
    }

    #[test]
    fn test_get_entries() {
        let rogs = get_test_rogs().iter().map(|e| e).collect::<Vec<_>>();
        debug!("{:#?}", rogs);
        assert_eq!(rogs.len(), 3);
    }

    #[test]
    fn test_get_rog() {
        let settings = Settings::new("rog.toml").unwrap();
        let rogs = get_test_rogs().iter().map(|e| e).collect::<Vec<_>>();
        let rogs = rogs
            .iter()
            .filter_map(|de| get_rog(de.path(), &settings))
            .collect::<Vec<_>>();
        debug!("{:#?}", rogs);
        assert_eq!(rogs.len(), 3);
    }

}
