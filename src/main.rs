use chrono::offset::TimeZone;
use chrono::{DateTime, Duration, Local};
use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, AppSettings, Arg,
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
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use tempfile::NamedTempFile;
use walkdir::{DirEntry, WalkDir};
#[macro_use]
extern crate rust_embed;

use settings::{Capture, Out, Settings};
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
    time_fix: DateTime<Local>,
    msg: Msg,
}
#[derive(Debug, Clone)]
struct Rog {
    name: String,
    path: PathBuf,
    capture: Capture,
    header_replace: bool,
    header_add: bool,
    parse: Vec<String>,
    add_time: Option<Duration>,
    start: Option<DateTime<Local>>,
    end: Option<DateTime<Local>>,
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
            "-s --start [START_TIME] 'yyyymmdd (or yyyymmddhhmmss)'",
        ))
        .arg(Arg::from_usage(
            "-e --end [END_TIME] 'yyyymmdd (or yyyymmddhhmmss)'",
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
        if let Some(out) = settings.out {
            settings.out = Some(Out {
                path: output.to_string(),
                ..out
            });
        }
    }
    if let Some(grep) = matches.value_of("grep") {
        if let Some(out) = settings.out {
            settings.out = Some(Out {
                grep_path: Some(grep.to_string()),
                ..out
            });
        }
    }
    // Filter lines by time.
    if let Some(start) = matches.value_of("start") {
        if let Some(out) = settings.out {
            settings.out = Some(Out {
                start: Some(
                    Local
                        .datetime_from_str(&(start.to_owned() + "0000"), "%Y%m%d%H%M")
                        .unwrap_or_else(|_| {
                            Local
                                .datetime_from_str(start, "%Y%m%d%H%M%S")
                                .expect(&format!("time parse error {:#?}", start))
                        }),
                ),
                ..out
            });
        }
    }
    if let Some(end) = matches.value_of("end") {
        if let Some(out) = settings.out {
            settings.out = Some(Out {
                end: Some(
                    Local
                        .datetime_from_str(&(end.to_owned() + "0000"), "%Y%m%d%H%M")
                        .unwrap_or_else(|_| {
                            Local
                                .datetime_from_str(end, "%Y%m%d%H%M%S")
                                .expect(&format!("time parse error {:#?}", end))
                        }),
                ),
                ..out
            });
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
    lines.sort_by_key(|l| l.time_fix);

    // Filter lines for time.
    // let out = settings.out.as_ref().expect("out setting is needed now !");
    // if let Some(start) = out.start {
    //     lines = lines
    //         .into_iter()
    //         .filter(|line| line.time >= start)
    //         .collect();
    // }
    // if let Some(end) = out.end {
    //     lines = lines.into_iter().filter(|line| line.time <= end).collect();
    // }

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

    #[cfg(not(target_os = "windows"))]
    {
        // debug!(
        // "{} conv {} -o {}",
        // &gonkf_path.to_str().unwrap(),
        // input.as_ref().to_str().unwrap(),
        // output.as_ref().to_str().unwrap()
        // );
        let out = Command::new(&gonkf_path)
            .arg("conv")
            .arg("-d")
            .arg("utf8")
            .arg(input.as_ref().to_path_buf())
            .arg("-o")
            .arg(output.as_ref().to_path_buf())
            .output()?;
    }

    #[cfg(target_os = "windows")]
    {
        let output = fs::File::create(output)?;
        let out = Command::new(&gonkf_path)
            .arg("-w")
            .arg(input.as_ref().to_path_buf())
            .stdout(Stdio::from(output))
            .spawn()?
            .wait_with_output()?;
        // fs::write(&output, &out.stdout)?;
    }

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
        let mut v = vec![line.time.format("%Y/%m/%d %H:%M:%S%.9f").to_string()];
        &out.fields.iter().for_each(|field| {
            let def = "".to_string();
            let f = line.msg.get(field).unwrap_or(&def);
            if field == "time_fix" {
                v.push(line.time_fix.format("%Y/%m/%d %H:%M:%S%.9f").to_string());
            } else {
                v.push(f.to_string());
            }
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
            let mut v = vec![line.time.format("%Y/%m/%d %H:%M:%S%.9f").to_string()];
            &out.fields.iter().for_each(|field| {
                let def = "".to_string();
                let f = line.msg.get(field).unwrap_or(&def);
                if field == "time_fix" {
                    v.push(line.time_fix.format("%Y/%m/%d %H:%M:%S%.9f").to_string());
                } else {
                    v.push(f.to_string());
                }
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
        parse: Vec<String>,
        add_time: Option<Duration>,
        start: Option<DateTime<Local>>,
        end: Option<DateTime<Local>>,
    ) -> Rog {
        Rog {
            name,
            path: Path::new(path.as_ref()).to_path_buf(),
            capture: capture.clone(),
            header_replace,
            header_add,
            parse,
            add_time,
            start,
            end,
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
        // self.fix_header(&tmp_file)?;
        // Open rog.
        // debug!("Open rog (csv) [{:#?}]", &tmp_file);
        let f = fs::File::open(tmp_file)?;
        let mut rdr = csv::ReaderBuilder::new()
            .flexible(true)
            .has_headers(true)
            .from_reader(f);
        if let Capture::Csv(header) = self.capture.clone() {
            rdr.set_headers(csv::StringRecord::from(header));
        }

        let mut lines: Vec<Line> = Vec::new();

        let mut rdr = rdr.deserialize();
        if self.header_replace {
            rdr.next();
        }

        for result in rdr {
            let mut msg: Msg = match result {
                Ok(x) => x,
                Err(e) => {
                    debug!("Deserialize error {:#?}", e);
                    continue;
                }
            };
            // Get time column.
            let time = match msg.get("time") {
                Some(x) => x,
                None => {
                    eprintln!("time column not found ! {:#?}", msg);
                    continue;
                }
            };
            // Parse time.
            let time =
                match self
                    .parse
                    .iter()
                    .find_map(|p| match Local.datetime_from_str(time, p) {
                        Ok(x) => Some(x),
                        Err(e) => {
                            eprintln!("time parse error {:#?} {:#?} {:#?}", time, &p, e);
                            None
                        }
                    }) {
                    Some(x) => x,
                    None => {
                        eprintln!("time parse error {:#?}", time);
                        continue;
                    }
                };

            let mut time_fix = time;
            if let Some(x) = self.add_time {
                time_fix = time_fix + x;
            }

            // Add if tiem_fix is in time.
            if (self.start.unwrap_or(time_fix) <= time_fix)
                && (time_fix <= self.end.unwrap_or(time_fix))
            {
                msg.insert("name".to_string(), self.name.to_string());
                msg.insert("path".to_string(), self.path.to_str().unwrap().to_string());
                // debug!("Insert time: {:#?}, time_fix: {:#?}, msg: {:#?}", &time, &time_fix, &msg);
                lines.push(Line {
                    time,
                    time_fix,
                    msg,
                });
            } else {
                // debug!("Skip time: {:#?}, time_fix: {:#?}, msg: {:#?}", time, time_fix, msg);
            }
        }

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
                    if let Some(caps) = re.captures(&r) {
                        let time = self.parse.iter().find_map(|p| {
                            if let Ok(time) = Local.datetime_from_str(
                                caps.name("time").expect("time is needed !").as_str(),
                                &p,
                            ) {
                                Some(time)
                            } else {
                                eprintln!("time parse error {:#?} {:#?}", &r, &p);
                                None
                            }
                        });

                        if let Some(time) = time {
                            let mut time_fix = time;
                            if let Some(dur) = self.add_time {
                                time_fix = time_fix + dur;
                            }
                            if (self.start.unwrap_or(time_fix) <= time_fix)
                                && (time_fix <= self.end.unwrap_or(time_fix))
                            {
                                let mut line = Line {
                                    time,
                                    time_fix,
                                    msg: HashMap::new(),
                                };

                                line.msg = re
                                    .capture_names()
                                    .flatten()
                                    .filter_map(|n| {
                                        Some((n.to_string(), caps.name(n)?.as_str().to_string()))
                                    })
                                    .collect();
                                line.msg.insert("name".to_string(), self.name.to_string());
                                line.msg.insert(
                                    "path".to_string(),
                                    self.path.to_str().unwrap().to_string(),
                                );

                                // debug!("{:#?}", line);
                                lines.push(line);
                            }
                        } else {
                            eprintln!("no time parse error {:#?} {:#?}", &r, &self.parse);
                        }
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
        self.lines.sort_by_key(|line| line.time_fix);
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
                rog.parse.clone(),
                rog.add_time,
                cfg.clone().out?.start,
                cfg.clone().out?.end,
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
        lines.sort_by_key(|l| l.time_fix);
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
        lines.sort_by_key(|l| l.time_fix);

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
        lines.sort_by_key(|l| l.time_fix);

        output_csv(lines, &settings).unwrap();
        let content = fs::read_to_string(&settings.out.unwrap().grep_path.unwrap()).unwrap();
        dbg!(&content);
        assert_eq!(content.lines().collect::<Vec<_>>().len(), 6);
    }
}
