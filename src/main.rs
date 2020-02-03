/// SIP002 encoding format could be found here: https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
///
/// In a nut shell, the format looks like below
///
///     SS-URI = ss://<method>:<password>@<hostname>:<port>[/][?plugin][#<tag>]
///
/// Among wchich, `<method>:<password>` is encoded with base64 method, some SS provider may also encode
/// `<method>:<password>@hostname:port` as a whole.
///
/// plugin is optional, but if it presents, then `/` is required.
///
/// tag is used as comments, optional.

extern crate clap;
extern crate base64;

use std::io::prelude::*;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::fs::File;
use std::io::{self, BufRead};
use clap::{App, Arg};
use serde_json as json;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Deserialize, Serialize)]
struct Server {
    method: String,
    password: String,
    hostname: String,
    port: u16,
    tag: String,
    options: HashMap<String, String>,
}

fn encode_server(srv: &Server) -> String {
    let info = base64::encode(&format!("{}:{}", srv.method.clone(), srv.password.clone()));
    let tag = srv.tag.clone();
    let tag: String = tag.as_bytes()
        .iter()
        .map(|e| {
                if e.is_ascii_alphanumeric() {
                format!("{}", *e as char)
                } else {
                    format!("%{:02x?}", e).to_uppercase()
                }
            })
        .collect::<String>();

    format!("ss://{info}@{hostname}:{port}{plug}{tag}",
            info = info,
            hostname = srv.hostname.clone(),
            port = srv.port,
            plug = {
                if srv.options.len() > 0 {
                    let mut options = format!("{}", "/?");
                    for (k, v) in srv.options.iter() {
                        options.push_str(&format!("{}={};", k, v));
                    }
                    if options.ends_with(';') { options.pop(); }
                    options
                } else {
                    "".to_string()
                }
            },
            tag = format!("#{}", tag),
    )
}

fn decode_uri(uri: &str) -> Result<String, &str> {
    let mut human_uri = String::new();
    let chars:Vec<_> = uri.chars().collect();
    let mut idx = 0;
    while idx < chars.len() {
        let c = chars[idx];
        match c {
            '%' => {
                let mut strbytes = vec![];
                loop {
                    let mut hexnum = String::new();
                    for _ in 0..2 {
                        idx += 1;
                        if idx < chars.len() {
                            hexnum.push(chars[idx]);
                        } else {
                            return Err("Invalid URL encoding!");
                        }
                    }

                    if let Ok(val) = u8::from_str_radix(&hexnum, 16) {
                        strbytes.push(val);
                    }

                    // check if there exists more percent-encoding data
                    idx += 1;
                    if idx < chars.len() {
                        let c = chars[idx];
                        // if there is no percent-encoding chars, break
                        if c != '%' {
                            if let Ok(savedstr) = String::from_utf8(strbytes) {
                                human_uri.push_str(&savedstr);
                            }
                            human_uri.push(c);
                            break;
                        }
                    // reach the last character of the uri, save analyzed chars
                    } else {
                        if let Ok(savedstr) = String::from_utf8(strbytes) {
                            human_uri.push_str(&savedstr);
                        }
                        break;
                    }
                }
            },
            _ => human_uri.push(c),
        }
        idx += 1;
    }
    return Ok(human_uri);
}

fn decode_sip002(sip002: &str) -> Result<Server, &str> {

    if !sip002.starts_with("ss://") {
        return Err("SIP002 should begin with ss://.");
    }

    let remain = sip002.trim_start_matches("ss://");

    let mut server = HashMap::new();

    // method and password section (required)
    let mut curtype = "INFO";
    server.insert(curtype, String::new());

    for c in remain.chars() {
        curtype = match c {
            meta @ '/' | meta @ '@' | meta @ '#' => {
                let meta = match meta {
                    // plugin section (optional)
                    '/' => "PLUG",
                    // hostname and port section (reuired)
                    '@' => "HOST",
                    // tag section (optional)
                    '#' => "TAG",
                    _ => panic!("NEVER BOOM"),
                };
                server.insert(meta, String::new());
                meta
            },
            _ => {
                server.entry(curtype).and_modify(|e| (*e).push(c));
                curtype
            },
        };
    }

    let mut config: Server = Default::default();

    // Checkout method and password, sometimes it may contain hostname and port
    let mut found_host = false;
    if let Ok(info) = base64::decode(&server["INFO"]) {
        if let Ok(info) = String::from_utf8(info) {
            let method_password = if info.find('@') != None {
                let v: Vec<_> = info.split('@').collect();
                let (v1, v2):(Vec<_>, Vec<_>) = (v[0].split(':').collect(), v[1].split(':').collect());
                config.hostname = v2[0].to_string();
                config.port = v2[1].to_string().parse::<u16>().unwrap();
                found_host = true;
                v1
            } else {
                let v: Vec<_> = info.split(':').collect();
                v
            };
            config.method = method_password[0].to_string();
            config.password = method_password[1].to_string();
        } else {
            return Err("Cannot convert bytes into string!");
        }
    } else {
        return Err("Cannot decode base64 encoding!");
    }

    // If we don't find HOST section, then try more
    if !found_host {
        if server.contains_key("HOST") {
            if let Some(entry) = server.get("HOST") {
                let v:Vec<_> = entry.split(':').collect();
                config.hostname = v[0].to_string();
                config.port = v[1].to_string().parse::<u16>().unwrap();
            }
        } else {
            return Err("Cannot found `hostname:passowrd` section!");
        }
    }

    let tag = server.entry("TAG").or_insert(config.hostname.clone());
    if let Ok(tag) = decode_uri(tag) {
        config.tag = tag;
    }

    if let Some(plug) = server.get("PLUG") {
        if let Ok(plug) = decode_uri(plug) {
            // Process non-empty plugin options
            if plug != "?" {
                if plug.starts_with("?plugin") {
                    let plug = &plug[1..]; // remove the first `?` character
                    let options: HashMap<_, _> = plug.split(';').map(|item| {
                            let kv: Vec<_> = item.split('=').collect();
                            (kv[0].to_string(), kv[1].to_string())
                    }).collect();
                    config.options = options;
                } else {
                    println!("{}", "Invalid plugin option is ignored.");
                }
            }
        } else {
            println!("{}", "Cannot decode plugin options, skipped!");
        }
    }

    Ok(config)
}

fn main() -> json::Result<()> {
    let matchs = App::new("ssurl")
        .version("0.1.0")
        .author("bugnofree <pwnkeeper@gmail.com>")
        .about("Convert SIP002 schema URL to variable configuration files.")
        .arg(Arg::with_name("input")
                .short("i")
                .long("--input")
                .value_name("FILE")
                .help("The path to sip002 file.")
                .takes_value(true))
        .arg(Arg::with_name("format")
                .short("F")
                .long("--format")
                .value_name("FORMAT")
                .help("android for shadowsocks-android, rust shdowsocks-rust, sip002 for standard SIP002 URL (valid for shadowsocksX-NG as well).")
                .takes_value(true))
        .arg(Arg::with_name("output")
                .short("o")
                .long("--output")
                .value_name("OUTPUT")
                .help("The file path to save the converted result.")
                .takes_value(true))
        .arg(Arg::with_name("uri")
                .value_name("uri")
                .help("Convert a signle SIP002 URL, if passed as command line parameter, put the URL in double quote."))
        .get_matches();

    let format = matchs.value_of("format").unwrap_or("android");

    let supported_format = vec!["rust", "android", "sip002"];
    if !supported_format.contains(&format) {
        println!("Supported formats: {}", supported_format.join(","));
        return Ok(());
    }

    let output = match matchs.value_of("output") {
        Some(output) => Path::new(output).to_path_buf(),
        None => {
            let dir = env::current_dir().unwrap();
            if let Some(output) = dir.to_str() {
                Path::new(output).join("result.txt")
            } else {
                panic!("Cannot get current directory!")
            }
        }
    };

    if let Some(uri) = matchs.value_of("uri") {
        if let Ok(server) = decode_sip002(uri) {
            println!("{:#?}", server);
        } else {
            println!("Invalid SIP002 URL!");
        }
    }

    if let Some(input) = matchs.value_of("input") {
        let file = match File::open(input) {
            Ok(file) => file,
            Err(err) => panic!("Couldn't open {}: {}",input, err),
        };
        let lines = io::BufReader::new(file).lines();

        let data: String = match format {
            "rust" => {
                let mut result = json::json!({
                    "servers": [],
                    "local_port": 1086,
                    "local_address": "127.0.0.1",
                });
                for line in lines {
                    if let Ok(line) = line {
                        if let Ok(srv) = decode_sip002(&line) {
                            if let Some(servers) = result["servers"].as_array_mut() {
                                servers.push(json::json!({
                                    "address": srv.hostname,
                                    "port": srv.port,
                                    "password": srv.password,
                                    "method": srv.method,
                                    "timeout": 300
                                }));
                            }
                        }
                    }
                }
                if let Ok(v) = json::to_string_pretty(&result) {
                    v
                } else {
                    String::new()
                }
            },

            "sip002" => {
                let mut result = String::new();
                for line in lines {
                    if let Ok(line) = line {
                        if let Ok(srv) = decode_sip002(&line) {
                            result.push_str(&encode_server(&srv));
                            result.push_str("\n");
                        }
                    }
                }
                result
            },

            "android" => {
                let mut result = json::json!([]);
                for line in lines {
                    if let Ok(line) = line {
                        if let Ok(srv) = decode_sip002(&line) {
                            let j = json::json!({
                                "server": srv.hostname,
                                "server_port": srv.port,
                                "password": srv.password,
                                "method": srv.method,
                                "remarks": srv.tag,
                                "route": "bypass-lan-china",
                                "remote_dns": "114.114.114.114",
                                "ipv6": true,
                                "proxy_apps": {
                                    "enabled": false
                                },
                                "udpdns": false
                            });
                            result.as_array_mut().unwrap().push(j);
                        }
                    }
                }
                if let Ok(v) = json::to_string_pretty(&result) {
                    v
                } else {
                    String::new()
                }
            },

            _ => panic!(format!("Only support format {}", format)),
        };

        if let Ok(mut f) = File::create(&output) {
            f.write(data.as_bytes()).expect(format!("Unable to write to {}", output.to_str().unwrap()).as_str()); 
            println!("The result is saved into {}", output.to_str().unwrap());
        }
    }

    Ok(())
}
