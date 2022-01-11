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

// A prompt built on Rustyline.

use crate::commands::Commands;
use rustyline::completion::Completer;
use rustyline::completion::Pair;
use rustyline::config::OutputStreamType;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::{self, MatchingBracketValidator, Validator};
use rustyline::Context;
use rustyline::{CompletionType, Config, EditMode, Editor};
use rustyline_derive::Helper;

#[derive(Helper)]
struct PromptHelper {
    commands: Commands,
    validator: MatchingBracketValidator,
    hinter: HistoryHinter,
}

impl PromptHelper {
    fn new(commands: Commands) -> Self {
        Self {
            validator: MatchingBracketValidator::new(),
            commands,
            hinter: HistoryHinter {},
        }
    }
}

impl Hinter for PromptHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(_line, _pos, _ctx)
    }
}

impl Highlighter for PromptHelper {}

impl Validator for PromptHelper {
    fn validate(
        &self,
        ctx: &mut validate::ValidationContext,
    ) -> rustyline::Result<validate::ValidationResult> {
        self.validator.validate(ctx)
    }

    fn validate_while_typing(&self) -> bool {
        self.validator.validate_while_typing()
    }
}

impl Completer for PromptHelper {
    type Candidate = Pair;
    fn complete(
        &self,
        line: &str,
        _pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let mut pairs = vec![];
        if line.is_empty() {
            for command in &self.commands.commands {
                pairs.push(Pair {
                    display: command.0.to_string(),
                    replacement: command.0.to_string(),
                })
            }
            return Ok((pairs.len(), pairs));
        }

        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() == 1 {
            // We're still completing the command name.
            for name in self.commands.commands.keys() {
                if name.starts_with(parts[0]) {
                    pairs.push(Pair {
                        display: name.to_string(),
                        replacement: name.to_string(),
                    })
                }
            }
        }

        Ok((0, pairs))
    }
}

pub struct RustyPrompt {
    rl: Editor<PromptHelper>,
}

impl<'a> RustyPrompt {
    pub fn new(commands: Commands) -> Self {
        let config = Config::builder()
            .history_ignore_space(true)
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Emacs)
            .output_stream(OutputStreamType::Stdout)
            .build();
        let helper = PromptHelper::new(commands);
        let mut rl = Editor::with_config(config);
        rl.set_helper(Some(helper));
        Self { rl }
    }

    pub fn readline(&mut self) -> Option<String> {
        loop {
            let prompt = ">>> ";
            let readline = self.rl.readline(prompt);
            match readline {
                Ok(line) => {
                    self.rl.add_history_entry(line.as_str());
                    return Some(line);
                }
                Err(ReadlineError::Interrupted) => {
                    return None;
                }
                Err(ReadlineError::Eof) => {
                    return None;
                }
                _ => {}
            }
        }
    }
}
