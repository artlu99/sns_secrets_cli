//! The `sns` CLI — port of `src/index.ts`. The launch environment is
//! scrubbed of secret-named variables before anything runs, and a stale
//! clipboard (whose 30-second clearer may have died) is swept.

use clap::{Parser, Subcommand};

use sns::commands;
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
    };

    if let Err(error) = result {
        eprintln!("{error}");
        if std::env::var("SNS_DEBUG").as_deref() == Ok("1") {
            eprintln!("{error:?}");
        }
        std::process::exit(1);
    }
}
