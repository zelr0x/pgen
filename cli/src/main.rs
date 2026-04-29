use clap::Parser;
use pgen::{self, ExposeSecret};

const MIN_RAW: i64 = 8;
const MAX_RAW: i64 = 4096;
const MIN: usize = MIN_RAW as usize;
const MAX: usize = MAX_RAW as usize;

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
    length: usize,
}

fn parse_number(s: &str) -> Result<usize, String> {
    match s.parse::<i64>() {
        Ok(n) if n < MIN_RAW => Err(format!("Length must be at least {} characters", MIN)),
        Ok(n) if n <= MAX_RAW => Ok(n as usize),
        Ok(_) => Err(format!("Length must be below {} characters", MAX)),
        Err(_) => Err("Invalid number format".to_string()),
    }
}

fn main() {
    let args = Args::parse();
    let n = args.length;
    assert!((MIN..=MAX).contains(&n));
    let p = pgen::generate(n);
    for &b in p.expose_secret() {
        print!("{}", b as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_parse_works() {
        let args = Args::parse_from(["pgen", "32"]);
        assert_eq!(args.length, 32);
    }

    #[test]
    fn arg_parse_rejects_small_n() {
        let r = Args::try_parse_from(["pgen", &format!("{}", MIN_RAW - 1)]);
        assert!(r.is_err());
    }

    #[test]
    fn arg_parse_rejects_large_n() {
        let r = Args::try_parse_from(["pgen", &format!("{}", MAX_RAW + 1)]);
        assert!(r.is_err());
    }
}
