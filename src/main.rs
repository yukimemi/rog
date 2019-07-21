use chrono::offset::TimeZone;
use chrono::{DateTime, Local};
use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, AppSettings, Arg,
    ArgMatches,
};
use csv;
use failure::Error;
use log::*;
use regex::Regex;
use serde_derive::Deserialize;
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
extern crate rust_embed;

use settings::{Capture, Settings};
use std::collections::HashMap;

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
    header_replace: bool,
    header_add: bool,
    parse: String,
    lines: Vec<Line>,
}

#[derive(Deserialize, Debug, Clone)]
struct LogCfg {
    #[serde(default = "set_loglevel")]
    rust_log: String,
}

fn set_loglevel() -> String {
    "info".to_string()
}

fn main() -> Result<()> {
    let log_cfg = envy::from_env::<LogCfg>()?;
    env::set_var("RUST_LOG", log_cfg.rust_log);
    let matches = app_from_crate!()
        .setting(AppSettings::DeriveDisplayOrder)
        .arg(
            Arg::from_usage("-c --cfg [CFG_PATH] 'config file (toml) path'")
                .default_value("rog.toml"),
        )
        .arg(Arg::from_usage(
            "-s --start [START_TIME] 'yyyymmdd (or yyyymmddhhmmssfff)'",
        ))
        .arg(Arg::from_usage(
            "-e --end [END_TIME] 'yyyymmdd (or yyyymmddhhmmssfff)'",
        ))
        .arg(Arg::from_usage("<PATH> 'log path'").default_value("."))
        .arg(Arg::from_usage("-o --output [OUTPUT_PATH] 'output path'"))
        .arg(Arg::from_usage(
            "-g --grep [GREP_OUTPUT_PATH] 'grep output path'",
        ))
        .get_matches();

    let cfg = matches.value_of("cfg").unwrap();

    // Read config.
    let mut settings = Settings::new(cfg)?;

    if settings.debug {
        env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::init();

    // debug!("{:#?}", &settings);
    if let Some(output) = matches.value_of("output") {
        match settings.out {
            Some(out) => {
                settings.out?.path = output.to_string();
            }
            None => {}
        }
    }

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

fn get_gonkf() -> Result<PathBuf> {
    let gonkf_path = env::temp_dir().join("gonkf.exe");

    if gonkf_path.exists() {
        return Ok(gonkf_path);
    }

    #[cfg(target_os = "windows")]
    let gonkf_data = Asset::get("nkf.exe").unwrap();
    // let gonkf_data = Asset::get("gonkf.exe").unwrap();

    #[cfg(not(target_os = "windows"))]
    let gonkf_data = Asset::get("gonkf").unwrap();

    let mut f = fs::File::create(&gonkf_path)?;
    f.write_all(&gonkf_data)?;
    f.flush()?;

    // Set executable permissions.
    #[cfg(not(target_os = "windows"))]
    {
        // debug!("chmod +x {}", &gonkf_path.to_str().unwrap());
        Command::new("chmod").arg("+x").arg(&gonkf_path).output()?;
    }

    Ok(gonkf_path)
}

fn to_utf8<P: AsRef<Path>>(input: P, output: P) -> Result<()> {
    let gonkf_path = get_gonkf()?;

    // debug!(
    // "{} conv {} -o {}",
    // &gonkf_path.to_str().unwrap(),
    // input.as_ref().to_str().unwrap(),
    // output.as_ref().to_str().unwrap()
    // );
    // let out = Command::new(&gonkf_path)
    // .arg("conv")
    // .arg("-d")
    // .arg("utf8")
    // .arg(input.as_ref().to_path_buf())
    // .arg("-o")
    // .arg(output.as_ref().to_path_buf())
    // .output()?;
    let out = Command::new(&gonkf_path)
        .arg("-w")
        .arg(input.as_ref().to_path_buf())
        .output()?;

    // let local_datetime: DateTime<Local> = Local::now();
    // let out_path = env::temp_dir().join(local_datetime.format("%Y%m%d_%H%M%S.%3f").to_string());
    // let ret = Command::new(&gonkf_path)
    // .arg("conv")
    // .arg("-d")
    // .arg("utf8")
    // .arg(input.as_ref().to_path_buf())
    // .arg("-o")
    // .arg(&out_path)
    // .output()?;
    // debug!(
    // "{} conv {} -o {}",
    // &gonkf_path.to_str().unwrap(),
    // input.as_ref().to_str().unwrap(),
    // out_path.to_str().unwrap()
    // );

    // debug!(
    // "{} -w {} > {}",
    // &gonkf_path.to_str().unwrap(),
    // input.as_ref().to_str().unwrap(),
    // &output.as_ref().to_str().unwrap()
    // );
    // debug!("{:#?}", &out);
    // dbg!(&out);
    fs::write(&output, &out.stdout)?;
    // let mut w = fs::File::create(&output)?;
    // w.write_all(&out.stdout)?;
    // w.flush()?;

    Ok(())
}

fn grep_lines(lines: Vec<&Line>, greps: Vec<HashMap<String, String>>) -> Vec<&Line> {
    // compile regex patterns.
    let res: Vec<HashMap<String, Regex>> = greps
        .iter()
        .map(|grep| {
            grep.iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        Regex::new(v).expect(&format!("grep pattern error {:#?}", v)),
                    )
                })
                .collect::<HashMap<String, Regex>>()
        })
        .collect();

    lines
        .into_iter()
        .filter(|line| {
            res.iter().any(|re| {
                re.iter()
                    .all(|(k, v)| v.is_match(line.msg.get(k).unwrap_or(&"".to_string())))
            })
        })
        .collect()
}

fn grep(content: String, greps: Vec<String>) -> Vec<String> {
    // Compile regex patterns.
    let res: Vec<Regex> = greps
        .iter()
        .map(|grep| Regex::new(grep).expect(&format!("grep pattern error {:#?}", grep)))
        .collect();

    content
        .lines()
        .filter(|line| res.iter().any(|re| re.is_match(&line)))
        .map(|line| line.to_string())
        .collect()
}

fn add_bom<P: AsRef<Path>>(path: P) -> Result<()> {
    // TODO: Add bom only no bom.
    let content = fs::read_to_string(&path)?;
    let mut w = fs::File::create(&path)?;
    w.write_all(&[0xEF, 0xBB, 0xBF])?;
    write!(w, "{}", content)?;
    w.flush()?;

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

    // Write header.
    let mut header = vec!["time".to_string()];
    header.append(&mut out.fields.clone());
    wtr.write_record(&header)?;

    let len = lines.len();
    lines.iter().for_each(|line| {
        // Make output records.
        let mut v = vec![line.time.format("%Y/%m/%d %H:%M:%S.%3f").to_string()];
        &out.fields.iter().for_each(|field| {
            let def = "".to_string();
            let f = line.msg.get(field).unwrap_or(&def);
            v.push(f.to_string());
        });
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

    // grep word.
    if let Some(greps) = &out.grep {
        // let content = fs::read_to_string(&out_path)?;
        // let grep_data = grep(content, greps.to_vec());

        let grep_data = grep_lines(lines.clone(), greps.to_vec());

        let grep_path = match &out.grep_path {
            Some(p) => p.as_str(),
            None => &out_path.to_str().unwrap(),
        };
        let grep_path = Path::new(grep_path);
        if let Some(p) = grep_path.parent() {
            fs::create_dir_all(p)?;
        }
        let mut wtr = csv::Writer::from_path(&grep_path)?;

        // Write header.
        wtr.write_record(&header)?;

        let len = grep_data.len();
        grep_data.into_iter().for_each(|line| {
            // Make output records.
            let mut v = vec![line.time.format("%Y/%m/%d %H:%M:%S.%3f").to_string()];
            &out.fields.iter().for_each(|field| {
                let def = "".to_string();
                let f = line.msg.get(field).unwrap_or(&def);
                v.push(f.to_string());
            });
            if let Err(e) = wtr.write_record(&v) {
                eprintln!("write_record error: {:#?}", e);
            }
        });
        wtr.flush()?;
        info!(
            "Write to csv [{}] ({} records)",
            &grep_path.to_str().unwrap(),
            len
        );

        if out.bom {
            add_bom(&grep_path)?;
        }
    }

    // Add bom if bom setting is true
    if out.bom {
        add_bom(&out_path)?;
    }

    Ok(())
}

impl Rog {
    fn new<P: AsRef<Path>>(
        name: String,
        path: P,
        capture: &Capture,
        header_replace: bool,
        header_add: bool,
        parse: String,
    ) -> Rog {
        Rog {
            name,
            path: Path::new(path.as_ref()).to_path_buf(),
            capture: capture.clone(),
            header_replace,
            header_add,
            parse,
            lines: vec![],
        }
    }

    fn fix_header<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // debug!("Open rog [{}]", path.as_ref().to_str().unwrap());
        if self.header_add {
            let content = fs::read_to_string(&path)?;
            let mut w = fs::File::create(&path)?;
            if let Capture::Csv(header) = &self.capture {
                writeln!(w, "{}", header.join(","))?;
                write!(w, "{}", content)?;
                w.flush()?;
            }
        }
        if self.header_replace {
            let content = fs::read_to_string(&path)?;
            let mut w = fs::File::create(&path)?;
            if let Capture::Csv(header) = &self.capture {
                writeln!(w, "{}", header.join(","))?;
                content.lines().enumerate().for_each(|(i, v)| {
                    if i == 0 {
                        // debug!("skip header !");
                    } else {
                        writeln!(w, "{}", v).unwrap();
                    }
                });
                w.flush()?;
            }
        }
        Ok(())
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
        self.fix_header(&tmp_file)?;
        // Open rog.
        // debug!("Open rog [{:#?}]", &tmp_file);
        let f = fs::File::open(tmp_file)?;
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(f);

        // rdr.records().next();
        // let pos = rdr.position().clone();
        // rdr.records().for_each(|r| debug!("{:#?}", r));
        // rdr.seek(pos)?;

        let lines: Vec<Line> = rdr
            .deserialize()
            .filter_map(|r: std::result::Result<Msg, csv::Error>| match r {
                Ok(mut r) => {
                    r.insert("name".to_string(), self.name.to_string());
                    if let Some(time) = r.get("time") {
                        Some(Line {
                            time: Local.datetime_from_str(time, &self.parse).expect(&format!(
                                "time parse error {:#?} {:#?}",
                                time, &self.parse
                            )),
                            msg: r,
                        })
                    } else {
                        eprintln!("time column not found ! {:#?}", r);
                        None
                    }
                }
                Err(e) => {
                    debug!("Deserialize error {:#?}", e);
                    None
                }
            })
            .collect();

        // debug!("{:#?}", lines);

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
            rdr.enumerate().for_each(|(idx, r)| match r {
                Ok(r) => {
                    let mut line = Line {
                        time: Local::now(),
                        msg: HashMap::new(),
                    };
                    if let Some(caps) = re.captures(&r) {
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
                            .filter_map(|n| {
                                Some((n.to_string(), caps.name(n)?.as_str().to_string()))
                            })
                            .collect();
                        line.msg.insert("name".to_string(), self.name.to_string());

                        // debug!("{:#?}", line);
                        lines.push(line);
                    } else {
                        debug!(
                            "Warn ! parse failed ! file: {:#?}, line: {:#?}, r: {:#?}, cap: {:#?}",
                            &self.path,
                            idx + 1,
                            &r,
                            &cap
                        );
                    }
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
                rog.header_replace,
                rog.header_add,
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
        dbg!(&rogs);
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
        // dbg!(&lines);

        assert_eq!(lines.len(), 26);
    }

    #[test]
    fn test_grep() {
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

        // grep
        if let Some(greps) = &settings.out.unwrap().grep {
            let lines = grep_lines(lines, greps.to_vec());
            assert_eq!(lines.len(), 5);
        }
    }

    #[test]
    fn test_grep_lines() {
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

        output_csv(lines, &settings).unwrap();
        let content = fs::read_to_string(&settings.out.unwrap().grep_path.unwrap()).unwrap();
        dbg!(&content);
        assert_eq!(content.lines().collect::<Vec<_>>().len(), 6);
    }
}
