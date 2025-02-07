use clap::{Parser, Subcommand};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

struct RuleFile {
    file_path: PathBuf,
}

impl RuleFile {
    fn new(file_path: PathBuf) -> Self {
        if !file_path.exists() {
            Self::initialize(&file_path);
        }
        Self { file_path }
    }

    fn initialize(path: &PathBuf) {
        let mut file =
            File::create(path).unwrap_or_else(|e| panic!("Failed to create file: {}", e));

        write!(
            file,
            "#-GENERATED- allowed ports managed by mfw-ports \n# \n\
            *filter\n\
            :INPUT ACCEPT [0:0]\n\
            :allowed-ports - [0:0]\n\
            -A INPUT -j allowed-ports\n\
            "
        )
        .unwrap();
    }

    fn read_contents(&self) -> Vec<String> {
        let file =
            File::open(&self.file_path).unwrap_or_else(|e| panic!("Failed to open file: {}", e));
        let reader = BufReader::new(file);
        reader
            .lines()
            .collect::<Result<Vec<String>, _>>()
            .unwrap_or_else(|e| panic!("Failed to read lines: {}", e))
    }

    fn write_contents(&self, contents: &[String]) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.file_path)
            .unwrap_or_else(|e| panic!("Failed to open file for writing: {}", e));

        for line in contents {
            writeln!(file, "{}", line).unwrap_or_else(|e| panic!("Failed to write line: {}", e));
        }
    }

    fn list_ports(&self) {
        let contents = self.read_contents();
        if contents.len() > 1 {
            let metadata = contents[1].trim_start_matches("# ");
            println!("Open ports: {}", metadata);
        }
    }

    fn add_port(&self, input: &str) {
        let mut contents = self.read_contents();

        let mut ports: Vec<String> = contents[1]
            .trim_start_matches("# ")
            .split(',')
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect();

        if !ports.contains(&input.to_string()) {
            ports.push(input.to_string());
            ports.sort();

            contents[1] = format!("# {}", ports.join(","));

            let rule = format!(
                "-A allowed-ports -p {} --dport {} -j ACCEPT",
                input.split('/').nth(1).unwrap_or("tcp"),
                input.split('/').next().unwrap()
            );
            contents.push(rule);

            self.write_contents(&contents);
        }
    }

    fn remove_port(&self, input: &str) {
        let mut contents = self.read_contents();

        let mut ports: Vec<String> = contents[1]
            .trim_start_matches("# ")
            .split(',')
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect();

        if let Some(pos) = ports.iter().position(|p| p == input) {
            ports.remove(pos);

            contents[1] = format!("# {}", ports.join(","));

            contents.retain(|line| {
                !line.contains(&format!(
                    "--dport {} -j ACCEPT",
                    input.split('/').next().unwrap()
                ))
            });

            self.write_contents(&contents);
        }
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "./ports.rule")]
    rulefile: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add { input: String },
    Remove { input: String },
    List,
}

fn main() {
    let cli = Cli::parse();
    let rule_file = RuleFile::new(cli.rulefile);

    match &cli.command {
        Commands::Add { input } => {
            rule_file.add_port(input);
            println!("Port {} added", input);
        }
        Commands::Remove { input } => {
            rule_file.remove_port(input);
            println!("Port {} removed", input);
        }
        Commands::List => {
            rule_file.list_ports();
        }
    }
}
