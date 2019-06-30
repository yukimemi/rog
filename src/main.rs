use chrono::offset::TimeZone;
use chrono::{DateTime, Local};
use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, AppSettings, Arg,
};
use csv;
use failure::Error;
use log::*;
use regex::Regex;
use settings::{Capture, Settings};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use tempfile::NamedTempFile;
use walkdir::{DirEntry, WalkDir};
#[macro_use]
extern crate bindata;
#[macro_use]
extern crate bindata_impl;
#[macro_use]
extern crate rust_embed;

mod settings;

type Result<T> = std::result::Result<T, Error>;
type Msg = HashMap<String, String>;

#[cfg(target_os = "windows")]
#[derive(RustEmbed)]
#[folder = "tool/windows"]
struct Asset;

#[cfg(target_os = "linux")]
#[derive(RustEmbed)]
#[folder = "tool/linux"]
struct Asset;

#[cfg(target_os = "macos")]
#[derive(RustEmbed)]
#[folder = "tool/macos"]
struct Asset;

#[derive(Debug, Clone)]
struct Lines(Vec<Line>);

#[derive(Debug, Clone)]
struct Line {
    time: DateTime<Local>,
    msg: Msg,
}
#[derive(Debug, Clone)]
struct Rog {
    name: String,
    path: PathBuf,
    capture: Capture,
    parse: String,
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

    // debug!("{:#?}", &settings);

    // Get logs.
    let input = matches.value_of("PATH").unwrap();
    let recv = get_entries(input);

    // Filter logs.
    let rogs: Vec<Rog> = recv
        .iter()
        .filter_map(|de| get_rog(de.path(), &settings))
        .collect();

    // Parse lines of rogs.
    let rogs: Vec<Rog> = rogs
        .iter()
        .map(|rog| rog.parse_lines())
        .map(|rog| match rog {
            Ok(rog) => Some(rog),
            Err(e) => {
                eprintln!("Error: {:#?}", e);
                None
            }
        })
        .flatten()
        .collect();

    // Sort rogs.
    let mut lines: Vec<&Line> = rogs.iter().map(|rog| &rog.lines).flatten().collect();
    lines.sort_by_key(|l| l.time);

    // Output rogs.
    // settings.out.
    output_csv(lines, &settings)?;

    Ok(())
}

fn to_utf8<P: AsRef<Path>>(input: P, output: P) -> Result<()> {
    #[cfg(target_os = "windows")]
    let gonkf_data = Asset::get("gonkf.exe").unwrap();

    #[cfg(not(target_os = "windows"))]
    let gonkf_data = Asset::get("gonkf").unwrap();

    let mut f = NamedTempFile::new()?;
    f.write_all(&gonkf_data)?;
    f.flush()?;

    let gonkf_path = f.into_temp_path();

    // Set executable permissions.
    #[cfg(not(target_os = "windows"))]
    {
        debug!("chmod +x {}", &gonkf_path.to_str().unwrap());
        Command::new("chmod").arg("+x").arg(&gonkf_path).output()?;
    }

    debug!(
        "{} conv {} -o {}",
        &gonkf_path.to_str().unwrap(),
        input.as_ref().to_str().unwrap(),
        output.as_ref().to_str().unwrap()
    );
    let out = Command::new(&gonkf_path)        .arg("conv")
        .arg(input.as_ref().to_path_buf())
        .arg("-o")
        .arg(output.as_ref().to_path_buf())
        .output()?;
    // dbg!(&out);
    Ok(())
}

fn output_csv(lines: Vec<&Line>, cfg: &Settings) -> Result<()> {
    // Open csv file.
    // TODO: use stdout !
    // let mut wtr: csv::writer::Writer<_> = match cfg.out {
    // Some(out) => csv::Writer::from_path(out.path)?,
    // None => csv::Writer::from_writer(std::io::stdout()),
    // };

    let out = &cfg.out.as_ref().expect("out setting is needed now !");
    let out_path = Path::new(&out.path);
    if let Some(p) = out_path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut wtr = csv::Writer::from_path(&out.path)?;
    // TODO write header.
    // if let Err(e) = wtr.write_record(&out.fields.expect("fields of out setting is needed now !")) {
    // eprintln!("write_record error: {:#?}", e);
    // }
    let len = lines.len();
    lines.into_iter().for_each(|line| {
        // Make output records.
        let mut v = vec![line.time.format("%Y/%m/%d %H:%M:%S.%3f").to_string()];
        match &out.fields {
            Some(fields) => fields.iter().for_each(|field| {
                let def = "".to_string();
                let f = line.msg.get(field).unwrap_or(&def);
                v.push(f.to_string());
            }),
            // TODO
            None => panic!("fields of out setting is needed now !"),
        }
        if let Err(e) = wtr.write_record(&v) {
            eprintln!("write_record error: {:#?}", e);
        }
    });
    wtr.flush()?;
    info!(
        "Write to csv [{}] ({} records)",
        &out_path.to_str().unwrap(),
        len
    );
    Ok(())
}

impl Rog {
    fn new<P: AsRef<Path>>(name: String, path: P, capture: &Capture, parse: String) -> Rog {
        Rog {
            name,
            path: Path::new(path.as_ref()).to_path_buf(),
            capture: capture.clone(),
            parse,
            lines: vec![],
        }
    }

    fn parse_lines(&self) -> Result<Self> {
        info!("Open rog [{}]", &self.path.to_str().unwrap());
        let mut rog = match &self.capture {
            Capture::Text(_) => self.parse_with_text()?,
            Capture::Csv(_) => self.parse_with_csv()?,
        };
        rog.sort();
        Ok(rog)
    }

    fn parse_with_csv(&self) -> Result<Self> {
        // Before open, translate to utf8.
        let tmp_file = NamedTempFile::new()?.into_temp_path();
        to_utf8(&self.path, &tmp_file.to_path_buf())?;
        // Open rog.
        let f = fs::File::open(tmp_file)?;
        let mut rdr = csv::Reader::from_reader(f);
        let mut lines: Vec<Line> = Vec::new();
        if let Capture::Csv(cap) = &self.capture {
            rdr.records().for_each(|r| match r {
                Ok(r) => {
                    let mut line = Line {
                        time: Local::now(),
                        msg: HashMap::new(),
                    };
                    line.msg.insert("name".to_string(), self.name.to_string());
                    cap.iter().for_each(|(k, v)| {
                        match r.get(*v) {
                            Some(col) => {
                                if k == "time" {
                                    line.time = Local.datetime_from_str(col, &self.parse).expect(
                                        &format!("Parse error {:#?} {:#?}", col, &self.parse),
                                    );
                                }
                                line.msg.insert(k.to_string(), col.to_string());
                            }
                            None => eprintln!("{:#?} has not {} column !", r, v),
                        };
                    });
                    lines.push(line);
                }
                Err(e) => eprintln!("{}", e),
            });
        }

        Ok(Rog {
            lines,
            ..self.clone()
        })
    }
    fn parse_with_text(&self) -> Result<Self> {
        // Before open, translate to utf8.
        let tmp_file = NamedTempFile::new()?.into_temp_path();
        to_utf8(&self.path, &tmp_file.to_path_buf())?;
        // Open rog.
        let f = fs::File::open(tmp_file)?;
        let rdr = BufReader::new(f).lines();
        let mut lines: Vec<Line> = Vec::new();
        // rdr.for_each(|line| debug!("{:#?}", line));
        if let Capture::Text(cap) = &self.capture {
            let re = Regex::new(cap)?;
            rdr.for_each(|r| match r {
                Ok(r) => {
                    let mut line = Line {
                        time: Local::now(),
                        msg: HashMap::new(),
                    };
                    let caps = re
                        .captures(&r)
                        .expect("parse error ! Is the regex capture strings collect ?");
                    line.time = Local
                        .datetime_from_str(
                            caps.name("time").expect("time is needed !").as_str(),
                            &self.parse,
                        )
                        .expect(&format!(
                            "Parse time error parse: {:#?} line: {:#?}",
                            &self.parse, &r
                        ));
                    line.msg = re
                        .capture_names()
                        .flatten()
                        .filter_map(|n| Some((n.to_string(), caps.name(n)?.as_str().to_string())))
                        .collect();
                    line.msg.insert("name".to_string(), self.name.to_string());

                    // debug!("{:#?}", line);
                    lines.push(line);
                }
                Err(e) => eprintln!("{}", e),
            });
        }
        // debug!("{:#?}", lines);

        Ok(Rog {
            lines,
            ..self.clone()
        })
    }

    fn sort(&mut self) {
        self.lines.sort_by_key(|line| line.time);
    }
}

fn get_rog<P: AsRef<Path>>(path: P, cfg: &Settings) -> Option<Rog> {
    cfg.rogs.iter().find_map(|rog| {
        let re = Regex::new(&rog.match_).unwrap();
        match re.is_match(path.as_ref().to_str().unwrap()) {
            true => Some(Rog::new(
                rog.name.to_string(),
                &path,
                &rog.capture,
                rog.parse.to_string(),
            )),
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

    // #[test]
    // fn test_main() {
    // assert_eq!(main().unwrap(), ());    // }

    #[test]
    fn test_get_entries() {
        let rogs = get_test_rogs().iter().map(|e| e).collect::<Vec<_>>();
        // debug!("{:#?}", rogs);
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
        // debug!("{:#?}", rogs);
        assert_eq!(rogs.len(), 3);
    }

    #[test]
    fn test_parse_with_csv() {
        let settings = Settings::new("rog.toml").unwrap();
        let rogs = get_test_rogs().iter().map(|e| e).collect::<Vec<_>>();
        let rogs = rogs
            .iter()
            .filter_map(|de| get_rog(de.path(), &settings))
            .filter_map(|rog| {
                if let Capture::Csv(_) = &rog.capture {
                    let rog = rog.parse_with_csv();
                    return Some(rog);
                }
                None
            })
            .collect::<Vec<_>>();
        // debug!("{:#?}", rogs);
        rogs.iter().for_each(|rog| match rog {
            Ok(rog) => match rog.name.as_str() {
                "system_evtx" => assert_eq!(rog.lines.len(), 6),
                "app_evtx" => assert_eq!(rog.lines.len(), 7),
                _ => panic!("error"),
            },
            Err(e) => panic!("error {:#?}", e),
        })
    }

    #[test]
    fn test_parse_with_text() {
        let settings = Settings::new("rog.toml").unwrap();
        let rogs = get_test_rogs().iter().map(|e| e).collect::<Vec<_>>();
        let rogs = rogs
            .iter()
            .filter_map(|de| get_rog(de.path(), &settings))
            .filter_map(|rog| {
                if let Capture::Text(_) = &rog.capture {
                    let rog = rog.parse_with_text();
                    return Some(rog);
                }
                None
            })
            .collect::<Vec<_>>();
        // debug!("{:#?}", rogs);
        rogs.iter().for_each(|rog| match rog {
            Ok(rog) => match rog.name.as_str() {
                "app" => assert_eq!(rog.lines.len(), 13),
                _ => panic!("error"),
            },
            Err(e) => panic!("error {:#?}", e),
        })
    }

    #[test]
    fn test_all_lines() {
        let settings = Settings::new("rog.toml").unwrap();
        let rogs = get_test_rogs().iter().map(|e| e).collect::<Vec<_>>();
        // Filter logs.
        let rogs: Vec<Rog> = rogs
            .iter()
            .filter_map(|de| get_rog(de.path(), &settings))
            .map(|rog| rog.parse_lines())
            .flatten()
            .collect();

        // Sort rogs.
        let mut lines: Vec<&Line> = rogs.iter().map(|rog| &rog.lines).flatten().collect();
        lines.sort_by_key(|l| l.time);
        dbg!(&lines);

        assert_eq!(lines.len(), 26);
    }
}
