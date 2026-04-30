use rand::{self, RngExt, CryptoRng, rngs::ThreadRng};
use secrecy::SecretSlice;

pub use secrecy::ExposeSecret;

const ALPHABET: &[u8] = b"0123456789-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Debug, Clone, Copy)]
pub struct Alphabet<'a>(&'a [u8]);

impl<'a> Alphabet<'a> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, i: usize) -> u8 {
        self.0[i]
    }

    pub fn as_slice(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> From<&'a [u8]> for Alphabet<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Alphabet(slice)
    }
}

impl<'a> From<&'a str> for Alphabet<'a> {
    fn from(s: &'a str) -> Self {
        Alphabet(s.as_bytes())
    }
}

pub struct PassGen<'a, R: CryptoRng> {
    rng: R,
    alphabet: Alphabet<'a>,
}

impl Default for PassGen<'static, rand::rngs::ThreadRng> {
    fn default() -> Self {
        Self {
            rng: rand::rng(),
            alphabet: ALPHABET.into(),
        }
    }
}

impl<'a, R: CryptoRng> PassGen<'a, R> {
    pub fn new(rng: R, alphabet: impl Into<Alphabet<'a>>) -> Self {
        Self {
            rng,
            alphabet: alphabet.into(),
        }
    }

    pub fn generate(&mut self, n: usize) -> SecretSlice<u8> {
        let a = self.alphabet;
        let mut s = Vec::with_capacity(n);
        for _ in 0..n {
            let i = self.rng.random_range(0..a.len());
            s.push(a.get(i));
        }
        SecretSlice::new(s.into())
    }
}

impl<'a> PassGen<'a, ThreadRng> {
    pub fn with_alphabet(alphabet: impl Into<Alphabet<'a>>) -> Self {
        PassGen::new(rand::rng(), alphabet)
    }
}

impl<R: CryptoRng> PassGen<'static, R> {
    pub fn with_rng(rng: R) -> PassGen<'static, R> {
        PassGen::new(rng, ALPHABET)
    }
}

pub fn generate(n: usize) -> SecretSlice<u8> {
    let mut g = PassGen::default();
    g.generate(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use rand::{Rng, TryCryptoRng, TryRng};
    use std::collections::HashMap;

    pub struct Always42Rng;

    impl TryRng for Always42Rng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl TryCryptoRng for Always42Rng {}

    #[test]
    fn default_works() {
        let k = 16;
        let mut g = PassGen::default();
        let p = g.generate(k);
        assert_eq!(p.expose_secret().len(), k);
        for &c in p.expose_secret() {
            assert!(ALPHABET.contains(&c), "Invalid char: {}", c);
        }
    }

    #[test]
    fn func_generate_works() {
        let k = 16;
        let p: secrecy::SecretBox<[u8]> = generate(k);
        assert_eq!(p.expose_secret().len(), k);
        for &c in p.expose_secret() {
            assert!(ALPHABET.contains(&c), "Invalid char: {}", c);
        }
    }

    #[test]
    fn with_rng_works() {
        let rng = Always42Rng {};
        let mut g = PassGen::with_rng(rng);
        let p = g.generate(8);
        for &c in p.expose_secret() {
            assert_eq!(c, ALPHABET[0]);
        }
    }

    #[test]
    fn generator_with_alphabet_works() {
        let alphabet = Alphabet::from("abc");
        let mut g = PassGen::with_alphabet(alphabet);
        let p = g.generate(8);
        for &c in p.expose_secret() {
            assert!(alphabet.as_slice().contains(&c));
        }
    }

    #[test]
    fn generator_respects_length() {
        let k = 16;
        let a = Alphabet::from("xyz");
        let mut g = PassGen::with_alphabet(a);
        let p = g.generate(k);
        assert_eq!(p.expose_secret().len(), k);
    }

    #[test]
    fn generator_4k() {
        let k = 4096;
        let mut g = PassGen::default();
        let r = g.generate(k);
        assert_eq!(r.expose_secret().len(), k)
    }

    #[test]
    fn distribution_is_roughly_uniform() {
        let alphabet = Alphabet::from("abcdef1234567890");
        let mut g = PassGen::new(rand::rng(), alphabet);

        let mut counts: HashMap<u8, usize> = HashMap::new();
        let samples: usize = 10_000;
        let p_len = 8;

        for _ in 0..samples {
            let p = g.generate(p_len);
            for &c in p.expose_secret() {
                *counts.entry(c).or_insert(0) += 1;
            }
        }

        let total_chars = samples * p_len;
        let expected_freq = total_chars as f64 / alphabet.len() as f64;

        for (&c, &count) in &counts {
            let ratio = count as f64 / expected_freq;
            assert!(
                (0.9..=1.1).contains(&ratio), // 10% tolerance.
                "Char {} frequency out of range: {} vs expected {}",
                c as char,
                count,
                expected_freq
            );
        }
    }

    #[test]
    fn crypto_passgen_works() {
        let k = 16;
        let mut g = PassGen::default();
        let p = g.generate(k);
        assert_eq!(p.expose_secret().len(), k);
        for &c in p.expose_secret() {
            assert!(ALPHABET.contains(&c), "Invalid char: {}", c);
        }
        assert_eq!(p.expose_secret().len(), k);
    }
}
