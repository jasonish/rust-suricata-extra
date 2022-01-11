// Copyright (C) 2022 Open Information Security Foundation
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc., 51
// Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

mod commands;
mod rustyprompt;

use crate::commands::Commands;
use crate::rustyprompt::RustyPrompt;
use commands::CommandParser;
use serde_json::json;
use suricata_client::{Client, ClientError, Response};

const DEFAULT_SC_PATH: &str = "/var/run/suricata/suricata-command.socket";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optflag("v", "verbose", "Verbose output");
    opts.optflag("h", "help", "Print this help menu");
    opts.optopt("c", "command", "Execute command and return JSON", "COMMAND");
    let matches = opts.parse(&args[1..])?;
    if matches.opt_present("h") {
        let brief = format!("Usage: {} [OPTIONS]", &args[0]);
        print!("{}", opts.usage(&brief));
        return Ok(());
    }
    let socket_filename = matches
        .free
        .get(0)
        .map(|s| s.as_ref())
        .unwrap_or_else(|| DEFAULT_SC_PATH)
        .to_string();
    let verbose = matches.opt_present("v");
    if verbose {
        println!("Using Suricata command socket: {}", &socket_filename);
    }

    let client = Client::connect(DEFAULT_SC_PATH, verbose)?;
    if let Some(command) = matches.opt_str("c") {
        run_batch_command(client, &command)
    } else {
        run_interactive(client)
    }
}

fn run_interactive(mut client: Client) -> Result<(), Box<dyn std::error::Error>> {
    client.send(&json!({"command": "command-list"}))?;
    let response = client.read()?;
    let commands: Vec<&str> = response["message"]["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    println!("Command list: {}", commands.join(", "));

    let commands = Commands::new();
    let command_parser = CommandParser::new();
    let mut prompt = RustyPrompt::new(commands);

    loop {
        match prompt.readline() {
            None => break,
            Some(line) => match command_parser._parse(&line) {
                Ok(command) => {
                    println!("{}", command);
                    match interactive_request_response(&mut client, &command) {
                        Ok(response) => {
                            let response: Response = serde_json::from_value(response).unwrap();
                            if response.status == "OK" {
                                println!("Success:");
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&response.message).unwrap()
                                );
                            } else {
                                println!("Error (status={})", response.status);
                                println!("{}", serde_json::to_string(&response.message).unwrap());
                            }
                            //
                            // if let Some(message) = response.get("message") {
                            //     println!("Success:");
                            //     println!("{}", serde_json::to_string_pretty(&message).unwrap());
                            // }
                        }
                        Err(err) => {
                            println!("{}", err);
                        }
                    }
                }
                Err(err) => {
                    println!("{}", err);
                }
            },
        }
    }

    Ok(())
}

fn run_batch_command(mut client: Client, command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let command_parser = CommandParser::new();
    let command = command_parser._parse(command)?;
    client.send(&command)?;
    let response = client.read()?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn interactive_request_response(
    client: &mut Client,
    msg: &serde_json::Value,
) -> Result<serde_json::Value, ClientError> {
    client.send(msg)?;
    let response = client.read()?;
    Ok(response)
}
