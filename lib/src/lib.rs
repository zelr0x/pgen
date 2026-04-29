use rand::{self, CryptoRng, Rng};
use rand_distr::{Distribution, uniform::Uniform};
use secrecy::SecretSlice;

pub use secrecy::ExposeSecret;

const ALPHABET: &[u8] = b"0123456789-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub fn generate(n: u16) -> SecretSlice<u8> {
    let mut rng = rand::rng();
    generate_with_crypto(&mut rng, n)
}

pub fn generate_with_crypto<R: Rng + CryptoRng>(rng: &mut R, n: u16) -> SecretSlice<u8> {
    generate_with(rng, n)
}

pub fn generate_with<R: Rng>(rng: &mut R, n: u16) -> SecretSlice<u8> {
    let s = Uniform::new(0, ALPHABET.len())
        .unwrap()
        .sample_iter(rng)
        .take(n as usize)
        .map(|i| ALPHABET[i])
        .collect::<Vec<u8>>();
    SecretSlice::new(s.into())
}
