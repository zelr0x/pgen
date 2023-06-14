use clap::Parser;
use rand::{
    distributions::{uniform::Uniform, Distribution},
};

const ALPHABET: &'static[u8] = "0123456789-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    .as_bytes();

/// Simple ASCII password generator.
/// Results consist of numbers, latin letters, hyphens and underscores.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(default_value_t = 16)]
    length: usize
}

fn main() {
    let args = Args::parse();
    Uniform::new(0, ALPHABET.len())
        .sample_iter(rand::thread_rng())
        .take(args.length)
        .map(|i| ALPHABET[i]) 
        .for_each(|c| print!("{}", c as char));
}
