use std::{io::Write, process::exit};

use clap::Parser;
use pgen::{self, Alphabet, ExposeSecret, PassGen, SpecialSet};
use zeroize::ZeroizeOnDrop;

const MIN_RAW: i64 = 8;
const MAX_RAW: i64 = 4096;
const MIN: usize = MIN_RAW as usize;
const MAX: usize = MAX_RAW as usize;

/// Simple ASCII password generator.
#[derive(Parser, Debug, ZeroizeOnDrop)]
#[command(name = "pgen", version, about, long_about = None)]
struct Args {
    /// Required password length, in characters
    #[arg(default_value_t = 16, value_parser=parse_number)]
    length: usize,

    /// Require at least one lowercase letter
    #[arg(short = 'l', long = "lower", default_value_t = false)]
    lower: bool,

    /// Require at least one uppercase letter
    #[arg(short = 'u', long = "upper", default_value_t = false)]
    upper: bool,

    /// Require at least one lowercase and one uppercase letter (same as -lu)
    #[arg(short = 'c', long = "case-mix", default_value_t = false)]
    case_mix: bool,

    /// Require at least one digit
    #[arg(short = 'd', long = "digit", default_value_t = false)]
    digit: bool,

    /// Require at least one special character
    #[arg(short = 's', long = "special", default_value_t = false)]
    special: bool,

    /// Require at least one special character from the full ASCII special character set
    #[arg(long = "special-full", default_value_t = false)]
    special_full: bool,

    /// Include characters in the alphabet
    #[arg(short = 'i', long = "include", value_parser = parse_nonempty_str)]
    include: Option<String>,

    /// Exclude characters from the alphabet
    #[arg(short = 'x', long = "exclude", value_parser = parse_nonempty_str)]
    exclude: Option<String>,

    /// Override the alphabet
    #[arg(short = 'a', long = "alphabet", value_parser = parse_nonempty_str)]
    alphabet: Option<String>,

    /// Specify the alphabet for special characters (ignored if --special-full is specified)
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
    debug_assert!((MIN..=MAX).contains(&n));

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
    let p = g.generate_checked(n).unwrap_or_else(|_| {
        eprintln!("Rules cannot be satisfied for a password of specified length");
        exit(3);
    });
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

    #[test]
    fn works() {
        let args = [
            "pgen",
            "-i",
            "c",
            "-a",
            "Aab1.",
            "--special-set",
            "#$%",
            "-scd",
            "8",
            "-x",
            "a",
        ];
        let r = Args::try_parse_from(args);
        assert!(r.is_ok());

        let args = r.unwrap();
        assert_eq!(args.alphabet, Some("Aab1.".to_owned()));
        assert_eq!(args.special_set, Some("#$%".to_owned()));
        assert_eq!(args.include, Some("c".to_owned()));
        assert_eq!(args.exclude, Some("a".to_owned()));
        assert!(args.case_mix);
        assert!(args.digit);
        assert!(args.special);
    }
}
