use clap::{Parser, Subcommand};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{fs, io};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,

    #[clap(short, long, default_value = "iptables.rule")]
    rulefile: String,

    /// Verbose output
    #[clap(short, long)]
    verbose: bool,

    #[clap(short, long)]
    dry_run: bool,

    #[clap(short, long)]
    no_cache: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a set of command, shorthand to "--verbose --dry-run apply"
    #[clap(aliases = &["gen", "preview", "build"])]
    Generate,

    /// Apply your rule
    #[clap(aliases = &["deploy", "ship", "up"])]
    Apply,

    /// Bring mfw to its clean state
    #[clap(aliases = &["disable", "down"])]
    Clean,

    /// Remove every mfw rule (why would you do it?)
    Uninstall,
}

fn exec_bash(script: &str) -> Result<(), io::Error> {
    if std::env::consts::OS == "linux" {
        let status = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Script failed with exit code: {status}"),
            ))
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bash execution is only supported on Linux",
        ))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let default_chains: HashMap<&str, Vec<&str>> = [
        ("filter", vec!["INPUT", "FORWARD", "OUTPUT"]),
        ("nat", vec!["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"]),
        (
            "mangle",
            vec!["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"],
        ),
        ("raw", vec!["PREROUTING", "OUTPUT"]),
    ]
    .iter()
    .cloned()
    .collect();

    let prefix = "_mfw_";

    // Load and process the rule file
    let rules = load_rules(&args.rulefile)?;

    // Generate the script

    match args.command {
        Commands::Generate => {
            let script = generate_script(args.verbose, &rules, &default_chains, prefix);
            println!("{script}");
        }
        Commands::Apply => {
            let script = generate_script(args.verbose, &rules, &default_chains, prefix);
            if args.verbose {
                println!("{script}");
            }
            if !args.dry_run {
                exec_bash(&script)?;
            }
            if !args.no_cache {
                File::create(args.rulefile + ".sh")
                    .unwrap()
                    .write_all(&script.as_bytes())
                    .unwrap();
            }
        }
        Commands::Clean => {
            let install_script = generate_clean_script(args.verbose, &default_chains, prefix);
            if args.verbose {
                println!("{install_script}");
            }
            if !args.dry_run {
                exec_bash(&install_script)?;
            }
        }
        Commands::Uninstall => {
            let uninstall_script = generate_uninstall_script(args.verbose, prefix);
            if args.verbose {
                println!("{uninstall_script}");
            }
            if !args.dry_run {
                exec_bash(&uninstall_script)?;
            }
        }
    }

    Ok(())
}

/// Load rules from the main file and resolve includes
fn load_rules(rule_file: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut rules = Vec::new();
    let base_dir = Path::new(rule_file).parent().unwrap_or(Path::new("."));
    let content = fs::read_to_string(rule_file)?;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("#include") || line.starts_with("#import") {
            let include_path = line.split_whitespace().nth(1).unwrap().trim_matches('"');
            let full_path = base_dir.join(include_path);
            let included_rules = load_rules(full_path.to_str().unwrap())?;
            rules.extend(included_rules);
        } else {
            rules.push(line.to_string());
        }
    }

    Ok(rules)
}

/// Generate the iptables script
fn generate_script(
    verbose: bool,
    rules: &[String],
    default_chains: &HashMap<&str, Vec<&str>>,
    prefix: &str,
) -> String {
    let mut script = generate_clean_script(verbose, default_chains, prefix);
    let mut defined_chains = HashSet::new();
    script.push('\n');

    // Process rules
    script.push_str("# Apply rules\n");
    let mut table: String = String::new();
    for line in rules {
        match line.chars().nth(0) {
            Some('#') => {
                script.push_str(line.as_str());
                script.push('\n');
            }
            Some('*') => {
                table = line.split_at(1).1.to_string();
            }
            Some(':') => {
                let chain = line
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .trim_start_matches(':');

                if let Some(default_chains) = default_chains.get(table.as_str()) {
                    if !default_chains.contains(&chain) && !defined_chains.contains(chain) {
                        script.push_str(&format!(
                            "iptables -t {table} -F {prefix}{chain} 2>/dev/null || true\n\
                            iptables -t {table} -X {prefix}{chain} 2>/dev/null || true\n\
                            iptables -t {table} -N {prefix}{chain}\n",
                        ));
                    }
                }

                defined_chains.insert(chain.to_string());
            }
            Some('-') => {
                let mut processed_line = line.clone();
                for chain in &defined_chains {
                    processed_line =
                        processed_line.replace(chain.as_str(), format!("{prefix}{chain}").as_str());
                }
                script.push_str(&format!("iptables -t {table} {processed_line}"));
                script.push('\n');
            }
            Some(_) => {}
            None => {}
        };
    }

    script
}

fn generate_uninstall_script(verbose: bool, prefix: &str) -> String {
    format!(
        "#!/usr/bin/bash\n\
        #\n\
        # MFW Generated\n\
        #\n\n\
        {}\n\
        # Clean up\n\
        for t in filter nat mangle raw security;do \
        iptables -S -t$t|grep \"\\-j {prefix}\"|sed 's/-A/-D/'|while read r;do iptables -t$t $r;done;\
        iptables -S -t$t|grep \"\\-N {prefix}\"|cut -d\\  -f2|while read c;do iptables -t$t -F $c&&iptables -t$t -X$c;done;\
        done\n\n",
        if verbose { "set -x" } else { "" }
    )
}

/// Generate the install script for default rules
fn generate_clean_script(
    verbose: bool,
    default_chains: &HashMap<&str, Vec<&str>>,
    prefix: &str,
) -> String {
    let mut script = String::new();

    script.push_str(generate_uninstall_script(verbose, prefix).as_str());

    script.push_str("# Create prefixed chains and setup jumps\n");
    for (table, chains) in default_chains {
        for chain in chains {
            script.push_str(&format!(
                "iptables -t {table} -N {prefix}{chain}\n\
                iptables -t {table} -A {chain} -j {prefix}{chain}\n"
            ));
        }
    }
    script
}
