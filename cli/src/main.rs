use clap::Parser;
use pgen::{self, ExposeSecret};

const MIN_RAW: i32 = 8;
const MAX_RAW: i32 = 4096;
const MIN: u16 = MIN_RAW as u16;
const MAX: u16 = MAX_RAW as u16;

/// Simple ASCII password generator.
///
/// Results consist of numbers, latin letters, hyphens and underscores.
///
/// Uses ChaCha12 CRNG for secure generation and low-level tricks
/// to avoid leaving passwords in memory.
#[derive(Parser, Debug)]
#[command(name = "pgen", author, version, about, long_about)]
struct Args {
    #[arg(default_value_t = 16, value_parser=parse_number)]
    length: u16,
}

fn parse_number(s: &str) -> Result<u16, String> {
    match s.parse::<i32>() {
        Ok(n) if n < MIN_RAW => Err(format!("Length must be at least {} characters", MIN)),
        Ok(n) if n <= MAX_RAW => Ok(n as u16),
        Ok(_) => Err(format!("Length must be below {} characters", MAX)),
        Err(_) => Err("Invalid number format".to_string()),
    }
}

fn main() {
    let args = Args::parse();
    let n = args.length;
    assert!((MIN..=MAX).contains(&n));
    let p = pgen::generate(n);
    for b in p.expose_secret() {
        print!("{}", *b as char);
    }
}
