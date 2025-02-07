use clap::{Parser, Subcommand};
use std::collections::{HashMap, HashSet};
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
}

#[derive(Subcommand, Debug)]
enum Commands {
    Generate,

    Apply,

    Install,
}

fn exec_bash(script: String) -> Result<(), io::Error> {
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
            let script = generate_script(&rules, &default_chains, prefix);
            println!("{script}");
        }
        Commands::Apply => {
            let script = generate_script(&rules, &default_chains, prefix);
            if args.verbose {
                println!("{script}");
            }
            if !args.dry_run {
                exec_bash(script)?;
            }
        }
        Commands::Install => {
            let install_script = generate_install_script(&default_chains, prefix);
            if args.verbose {
                println!("{install_script}");
            }
            if !args.dry_run {
                exec_bash(install_script)?;
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
    rules: &[String],
    default_chains: &HashMap<&str, Vec<&str>>,
    prefix: &str,
) -> String {
    let mut script = generate_install_script(default_chains, prefix);
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
                defined_chains.insert(chain.to_string());

                if let Some(default_chains) = default_chains.get(table.as_str()) {
                    if !default_chains.contains(&chain) {
                        // Clean up and recreate the custom chain
                        script.push_str(&format!(
                            "iptables -t filter -F {prefix}{chain} 2>/dev/null || true\n\
                            iptables -t filter -X {prefix}{chain} 2>/dev/null || true\n\
                            iptables -t filter -N {prefix}{chain}\n",
                        ));
                        continue;
                    }
                }
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

/// Generate the install script for default rules
fn generate_install_script(default_chains: &HashMap<&str, Vec<&str>>, prefix: &str) -> String {
    let mut script = String::new();
    script.push_str(&format!(
        "#!/usr/bin/bash\n\
        # Cleanup existing prefixed chains\n\
        for table in filter nat mangle raw security; do\n\
        iptables -t $table -S | grep -E '^:({prefix}|\\S+_{prefix})' | cut -d' ' -f1 | sed 's/://' | while read chain; do\n\
        iptables -t $table -F \"$chain\"\n\
        iptables -t $table -X \"$chain\"\n\
        done\n\
        done\n"
    ));

    script.push_str("# Create prefixed chains and setup jumps\n");
    for (table, chains) in default_chains {
        for chain in chains {
            script.push_str(&format!(
                "iptables -t {table} -N {prefix}{chain} 2>/dev/null || true\n\
                iptables -t {table} -A {chain} -j {prefix}{chain}\n"
            ));
        }
    }
    script
}
