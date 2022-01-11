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

use serde_json::json;
use std::{collections::HashMap, str::FromStr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandParseError {
    #[error("Unknown command {0}")]
    UnknownCommand(String),
    #[error("`{0}`")]
    Other(String),
}

#[derive(Debug, Copy, Clone)]
pub enum ArgType {
    String,
    Number,
    Boolean,
}

#[derive(Clone)]
pub struct Commands {
    pub commands: HashMap<String, Vec<(String, bool, ArgType)>>,
}

impl Commands {
    pub fn new() -> Self {
        let mut parser = Self {
            commands: HashMap::new(),
        };
        parser.register_commands();
        parser
    }

    pub fn register_command<T: AsRef<str>>(&mut self, name: T, args: &[(T, bool, ArgType)]) {
        let args: Vec<(String, bool, ArgType)> = args
            .iter()
            .map(|e| (e.0.as_ref().to_string(), e.1, e.2))
            .collect();
        self.commands.insert(name.as_ref().to_string(), args);
    }

    fn register_commands(&mut self) {
        use ArgType::{Boolean, Number, String};

        self.register_command("command-list", &[]);

        self.register_command("help", &[]);

        self.register_command("iface-list", &[]);

        self.register_command("iface-stat", &[("iface", true, String)]);

        self.register_command(
            "pcap-file",
            &[
                ("filename", true, String),
                ("output-dir", true, String),
                ("tenant", false, Number),
                ("continuous", false, Boolean),
                ("delete-when-done", false, Boolean),
            ],
        );

        self.register_command(
            "pcap-file-continuous",
            &[
                ("filename", true, String),
                ("output-dir", true, String),
                ("continuous", true, Boolean),
            ],
        );

        self.register_command("memcap-list", &[]);
        self.register_command("memcap-show", &[("config", true, String)]);

        self.register_command(
            "memcap-set",
            &[("config", true, String), ("memcap", true, String)],
        );

        self.register_command("uptime", &[]);

        self.register_command("version", &[]);
        self.register_command("running-mode", &[]);
        self.register_command("capture-mode", &[]);
        self.register_command("reload-rules", &[]);
        self.register_command("ruleset-reload-nonblocking", &[]);
        self.register_command("ruleset-stats", &[]);
    }
}

pub struct CommandParser {
    pub commands: Commands,
}

impl CommandParser {
    pub fn new() -> Self {
        Self {
            commands: Commands::new(),
        }
    }

    pub fn _parse(&self, input: &str) -> Result<serde_json::Value, CommandParseError> {
        let parts: Vec<&str> = input.split(' ').map(|s| s.trim()).collect();
        if parts.is_empty() {
            return Err(CommandParseError::Other("No command provided".to_string()));
        }
        let command = parts[0];
        let args = &parts[1..];

        let spec = match self.commands.commands.get(command) {
            None => {
                return Err(CommandParseError::UnknownCommand(command.to_string()));
            }
            Some(spec) => spec,
        };

        // Calculate the number of required arguments for better error reporting.
        let required = spec.iter().filter(|e| e.1).count();

        let mut json_args = HashMap::new();
        for (i, spec) in spec.iter().enumerate() {
            if let Some(arg) = args.get(i) {
                let val = match spec.2 {
                    ArgType::String => serde_json::Value::String(arg.to_string()),
                    ArgType::Boolean => match *arg {
                        "true" | "1" => true.into(),
                        "false" | "0" => false.into(),
                        _ => {
                            return Err(CommandParseError::Other(format!(
                                "Bad argument: value is not a boolean: {}",
                                arg
                            )));
                        }
                    },
                    ArgType::Number => {
                        let number = serde_json::Number::from_str(arg).map_err(|_| {
                            CommandParseError::Other(format!("Bad argument: not a number: {}", arg))
                        })?;
                        serde_json::Value::Number(number)
                    }
                };
                json_args.insert(&spec.0, val);
            } else if spec.1 {
                return Err(CommandParseError::Other(format!(
                    "Missing arguments: expected at least {}",
                    required
                )));
            }
        }

        let mut message = json!({ "command": command });
        if !json_args.is_empty() {
            message["arguments"] = json!(json_args);
        }

        Ok(message)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parser() {
        let parser = CommandParser::new();
        let _command = parser._parse("iface-list").unwrap();
    }
}
