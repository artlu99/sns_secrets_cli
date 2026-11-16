//! The `sns` CLI — port of `src/index.ts`. The launch environment is
//! scrubbed of secret-named variables before anything runs, and a stale
//! clipboard (whose 30-second clearer may have died) is swept.

use clap::{Parser, Subcommand};

use sns::commands;
use sns::completion::{complete_with_cache, completion_script};
use sns::errors::UserError;

#[derive(Parser)]
#[command(
    name = "sns",
    version = env!("CARGO_PKG_VERSION"),
    about = "Read Standard Notes with an encrypted local cache; run with no command for an interactive picker"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// check runtime, keychain, session, and cache
    Doctor,
    /// log in and sync notes into the encrypted cache
    Login,
    /// revoke the session and delete local secrets
    Logout {
        /// also delete the encrypted cache
        #[arg(long)]
        delete_cache: bool,
    },
    /// delete the entire local config directory (offline; never touches the server)
    Purge {
        /// skip the confirmation prompt (required when not a terminal)
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// pull and decrypt notes into the encrypted cache
    Sync,
    /// list tags and folders (read-only)
    Tags,
    /// list notes (env-style setting count per note; --all for everything)
    List {
        /// filter by content type, e.g. Note
        #[arg(long = "type")]
        content_type: Option<String>,
        /// only notes under this tag or folder
        #[arg(long)]
        tag: Option<String>,
        /// max rows
        #[arg(long, default_value = "100")]
        limit: String,
        /// list everything, including key-bearing items
        #[arg(long)]
        all: bool,
    },
    /// search decrypted title and content
    Search {
        query: String,
        /// treat the query as a regular expression
        #[arg(long)]
        regex: bool,
        /// max hits
        #[arg(long, default_value = "50")]
        limit: String,
        /// include key-bearing items
        #[arg(long)]
        all: bool,
    },
    /// show a note's setting keys and prose (values stay in the cache)
    Show {
        /// uuid or title prefix
        id: String,
        /// print without paging
        #[arg(long)]
        no_pager: bool,
    },
    /// copy one setting value to the clipboard via OSC 52; clears in 30s
    Copy {
        /// uuid or title prefix
        id: String,
        /// exact setting name; omit to list the note's keys
        key: Option<String>,
    },
    /// write one setting value to a 0600 file (agent handoff; the value is never displayed)
    Sink {
        /// uuid or title prefix
        id: String,
        /// exact setting name
        key: String,
        /// destination file (created 0600; must not exist without --force)
        path: String,
        /// overwrite an existing file (still 0600)
        #[arg(long)]
        force: bool,
    },
    /// print bash or zsh tab-completion script
    Completion {
        /// bash or zsh
        shell: String,
    },
    /// hidden: shell scripts call this; prints one candidate per line
    #[command(name = "__complete", hide = true)]
    Complete {
        /// index into the word list (COMP_CWORD)
        #[arg(long)]
        cword: usize,
        /// COMP_WORDS / zsh words
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        words: Vec<String>,
    },
}

fn parse_limit(raw: &str) -> Result<usize, UserError> {
    let limit: usize = raw
        .parse()
        .map_err(|_| UserError("--limit must be a positive integer".into()))?;
    if limit < 1 {
        return Err(UserError("--limit must be a positive integer".into()));
    }
    Ok(limit)
}

fn main() {
    sns::env::scrub_process_env();
    sns::clipboard::maybe_clear_stale_clipboard();

    let cli = Cli::parse();
    let result = match cli.command {
        None => commands::browse_command(),
        Some(Commands::Doctor) => {
            std::process::exit(commands::doctor_command());
        }
        Some(Commands::Login) => commands::login_command(),
        Some(Commands::Logout { delete_cache }) => commands::logout_command(delete_cache),
        Some(Commands::Purge { yes }) => commands::purge_command(yes),
        Some(Commands::Sync) => commands::sync_command(),
        Some(Commands::Tags) => commands::tags_command(),
        Some(Commands::List { content_type, tag, limit, all }) => match parse_limit(&limit) {
            Ok(limit) => commands::list_command(content_type.as_deref(), tag.as_deref(), limit, all),
            Err(error) => Err(error),
        },
        Some(Commands::Search { query, regex, limit, all }) => match parse_limit(&limit) {
            Ok(limit) => commands::search_command(&query, regex, limit, all),
            Err(error) => Err(error),
        },
        Some(Commands::Show { id, no_pager }) => commands::show_command(&id, no_pager),
        Some(Commands::Copy { id, key }) => commands::copy_command(&id, key.as_deref()),
        Some(Commands::Sink { id, key, path, force }) => sns::sink::sink_command(&id, &key, &path, force),
        Some(Commands::Completion { shell }) => match completion_script(&shell) {
            Ok(script) => {
                print!("{script}");
                Ok(())
            }
            Err(error) => Err(error),
        },
        Some(Commands::Complete { cword, words }) => {
            let candidates = complete_with_cache(&words, cword);
            if !candidates.is_empty() {
                println!("{}", candidates.join("\n"));
            }
            Ok(())
        }
    };

    if let Err(error) = result {
        // SNS_DEBUG=1 prints stack traces on the TS side; Result errors carry
        // no backtrace here, so the Display message is all we have.
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;
    use sns::completion::SUBCOMMANDS;

    #[test]
    fn completion_subcommands_match_the_clap_surface() {
        let declared: Vec<String> = Cli::command()
            .get_subcommands()
            .filter(|command| !command.is_hide_set())
            .map(|command| command.get_name().to_string())
            .collect();
        let completion_list: Vec<String> = SUBCOMMANDS
            .iter()
            .filter(|name| **name != "help")
            .map(|name| (*name).to_string())
            .collect();
        assert_eq!(completion_list, declared);
    }
}
