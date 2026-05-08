use std::{io::Write, process::exit};

use clap::Parser;
use pgen::{self, Alphabet, ExposeSecret, PassGen, SpecialSet};
use zeroize::ZeroizeOnDrop;

const MIN_RAW: i64 = 8;
const MAX_RAW: i64 = 4096;
const MIN: usize = MIN_RAW as usize;
const MAX: usize = MAX_RAW as usize;

/// Simple ASCII password generator.
///
/// Results depend on the alphabet and options.
/// Default alphabet consists of numbers, latin letters, hyphens
/// and underscores.
///
/// Uses ChaCha20 CRNG for secure generation and tries its best
/// to avoid leaving passwords in memory.
#[derive(Parser, Debug, ZeroizeOnDrop)]
#[command(name = "pgen", author, version, about, long_about)]
struct Args {
    /// Length of the password
    #[arg(default_value_t = 16, value_parser=parse_number)]
    length: usize,

    /// If true, generated password will have at least one lowercase letter
    #[arg(short = 'l', long = "lower", default_value_t = false)]
    lower: bool,

    /// If true, generated password will have at least one uppercase letter
    #[arg(short = 'u', long = "upper", default_value_t = false)]
    upper: bool,

    /// If true, generated password will have at least one lower case letter
    /// as well as at least one upper case letter. Same as -lu
    #[arg(short = 'c', long = "case-mix", default_value_t = false)]
    case_mix: bool,

    /// If true, generated password will have at least one digit
    #[arg(short = 'd', long = "digit", default_value_t = false)]
    digit: bool,

    /// If true, generated password will have at least one special character
    #[arg(short = 's', long = "special", default_value_t = false)]
    special: bool,

    /// If true, generated password will have at least one special character
    /// from the full ASCII special character set.
    #[arg(long = "special-full", default_value_t = false)]
    special_full: bool,

    /// Characters that must always be present
    #[arg(short = 'm', long = "must", value_parser = parse_nonempty_str)]
    must: Option<String>,

    /// Characters to include in the alphabet
    #[arg(short = 'i', long = "include", value_parser = parse_nonempty_str)]
    include: Option<String>,

    /// Characters to exclude from the alphabet
    #[arg(short = 'x', long = "exclude", value_parser = parse_nonempty_str)]
    exclude: Option<String>,

    /// Alphabet used to generate the password
    #[arg(short = 'a', long = "alphabet", value_parser = parse_nonempty_str)]
    alphabet: Option<String>,

    /// Custom alphabet to use for special characters. --special-full overrides
    /// this option.
    #[arg(long = "special-set", value_parser = parse_nonempty_str)]
    special_set: Option<String>,
}

fn parse_number(s: &str) -> Result<usize, String> {
    match s.parse::<i64>() {
        Ok(n) if n < MIN_RAW => Err(format!("Length must be at least {} characters", MIN)),
        Ok(n) if n <= MAX_RAW => Ok(n as usize),
        Ok(_) => Err(format!("Length must be below {} characters", MAX)),
        Err(_) => Err("Invalid number format".to_string()),
    }
}

fn parse_nonempty_str(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("Argument specified without associated value".to_string())
    } else {
        Ok(s.to_owned())
    }
}

fn main() {
    let args = Args::parse();
    let n = args.length;
    // Cheap defensive check that parsers were applied as expected.
    assert!((MIN..=MAX).contains(&n));

    // Empty means not specified, ensured by parse_nonempty_str.
    let mut a = args
        .alphabet
        .as_ref()
        .map(|s| s.as_bytes().try_into().unwrap()) // Unwrap is safe parse_nonempty_str
        .unwrap_or(Alphabet::default());
    if let Some(cs) = args.include.as_ref() {
        a.add(cs.as_bytes());
    }
    if let Some(cs) = args.exclude.as_ref() {
        a.remove(cs.as_bytes()).unwrap_or_else(|_| {
            eprintln!("Alphabet became empty after exclusion");
            exit(2);
        });
    }

    let ss = args
        .special_set
        .as_ref()
        .map(|ss| {
            if args.special_full {
                SpecialSet::Full
            } else {
                SpecialSet::Custom(ss.as_bytes().try_into().unwrap()) // Unwrap is safe parse_nonempty_str
            }
        })
        .unwrap_or(SpecialSet::Safe);
    let mut g = PassGen::new(a, ss);
    if args.case_mix || args.upper {
        g = g.with_upper().unwrap_or_else(|_| {
            eprintln!("Alphabet does not contain any uppercase letters");
            exit(2);
        })
    }
    if args.case_mix || args.lower {
        g = g.with_lower().unwrap_or_else(|_| {
            eprintln!("Alphabet does not contain any lowercase letters");
            exit(2);
        })
    }
    if args.digit {
        g = g.with_digit().unwrap_or_else(|_| {
            eprintln!("Alphabet does not contain any digits");
            exit(2);
        })
    }
    if args.special {
        g = g.with_special().unwrap_or_else(|_| {
            eprintln!("Alphabet does not contain any special characters");
            exit(2);
        })
    }
    let p = g.generate(n);
    std::io::stdout().write_all(p.expose_secret()).unwrap();
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
