#![forbid(unsafe_code)]

mod byteset;

use std::ops::Index;

use rand::{
    self, CryptoRng, RngExt, SeedableRng,
    rngs::{ChaCha20Rng, SysRng},
    seq::SliceRandom,
};
use secrecy::SecretSlice;

pub use secrecy::ExposeSecret;

use crate::byteset::{ByteSet, MutByteSet};

const ALPHABET: &[u8] = b"0123456789-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SPECIALS_DEFAULT: &[u8] = b"-_";
const SPECIALS_SAFE: &[u8] = b"!#$%&()*+,-./:;=?@[]^_{}~";
const SPECIALS: &[u8] = b" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

const ALPHABET_SET: ByteSet = ByteSet::new(ALPHABET);
const SPECIALS_DEFAULT_SET: ByteSet = ByteSet::new(SPECIALS_DEFAULT);
const SPECIALS_SAFE_SET: ByteSet = ByteSet::new(SPECIALS_SAFE);
const SPECIALS_SET: ByteSet = ByteSet::new(SPECIALS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A rule cannot be satisfied with the current alphabet.
    UnsatisfiableRule,
    /// Alphabet is empty after applying rules.
    EmptyAlphabet,
}

/// Alphabet is a non-empty set of characters.
#[derive(Debug, Clone)]
pub struct Alphabet {
    chars: Vec<u8>,
    set: ByteSet,
}

impl Alphabet {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.chars.as_ref()
    }

    pub fn new(slice: &[u8]) -> Result<Self, Error> {
        if slice.is_empty() {
            Err(Error::EmptyAlphabet)
        } else {
            Ok(Self::new_normalized(slice))
        }
    }

    pub fn add(&mut self, slice: &[u8]) {
        let chars = &mut self.chars;
        let mut set: MutByteSet = self.set.into();
        for &b in slice {
            if !set.contains(b) {
                set.insert(b);
                chars.push(b);
            }
        }
        self.set = set.into();
    }

    pub fn remove(&mut self, slice: &[u8]) -> Result<(), Error> {
        let chars = &mut self.chars;
        let set = self.set.diff_slice(slice);
        if set.is_empty() {
            return Err(Error::EmptyAlphabet);
        }
        self.set = set;
        chars.retain(|&c| set.contains(c));
        Ok(())
    }

    fn new_unchecked(chars: &[u8], set: ByteSet) -> Self {
        debug_assert!(!chars.is_empty());
        Self {
            chars: chars.to_vec(),
            set,
        }
    }

    fn new_normalized(chars: &[u8]) -> Self {
        let mut set = MutByteSet::default();
        let mut out = Vec::with_capacity(chars.len());
        for &b in chars {
            if !set.contains(b) {
                set.insert(b);
                out.push(b);
            }
        }
        Self {
            chars: out,
            set: set.into(),
        }
    }
}

impl Index<usize> for Alphabet {
    type Output = u8;

    #[inline]
    fn index(&self, idx: usize) -> &Self::Output {
        &self.chars[idx]
    }
}

impl Default for Alphabet {
    fn default() -> Self {
        Self::new_unchecked(ALPHABET, ALPHABET_SET)
    }
}

impl TryFrom<Vec<u8>> for Alphabet {
    type Error = Error;

    fn try_from(chars: Vec<u8>) -> Result<Self, Self::Error> {
        if chars.is_empty() {
            Err(Error::EmptyAlphabet)
        } else {
            Ok(Alphabet::new_normalized(&chars))
        }
    }
}

impl TryFrom<&[u8]> for Alphabet {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::new(slice)
    }
}

impl TryFrom<&str> for Alphabet {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s.as_bytes())
    }
}

impl From<SpecialSet> for Alphabet {
    fn from(s: SpecialSet) -> Self {
        match s {
            SpecialSet::Default => Self::new_unchecked(SPECIALS_DEFAULT, SPECIALS_DEFAULT_SET),
            SpecialSet::Safe => Self::new_unchecked(SPECIALS_SAFE, SPECIALS_SAFE_SET),
            SpecialSet::Full => Self::new_unchecked(SPECIALS, SPECIALS_SET),
            SpecialSet::Custom(a) => a,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SpecialSet {
    /// Default is the safest scheme that includes only hyphen and underscore.
    Default,
    /// Safe includes all special characters except space, backtick, backslash,
    /// single and double quotes, pipe, and angle brackets.
    Safe,
    /// Full includes all special characters present in Latin1 character set.
    Full,
    /// Custom allows to specify a custom special alphabet.
    Custom(Alphabet),
}

/// Rules allow to constrain the generator results.
#[derive(Debug, Clone)]
enum Rule {
    MustInclude(Alphabet),
}

/// PassGen is a password generator.
pub struct PassGen<R: CryptoRng> {
    rng: R,
    alphabet: Alphabet,
    special_set: SpecialSet,
    rules: Vec<Rule>,
}

impl<R: CryptoRng> PassGen<R> {
    pub fn new_with_rng<A>(rng: R, alphabet: A, special_set: SpecialSet) -> Self
    where
        A: Into<Alphabet>,
    {
        Self {
            rng,
            alphabet: alphabet.into(),
            special_set,
            rules: Vec::new(),
        }
    }

    pub fn try_new<A>(rng: R, alphabet: A, special_set: SpecialSet) -> Result<Self, A::Error>
    where
        A: TryInto<Alphabet>,
    {
        alphabet
            .try_into()
            .map(|alphabet| Self::new_with_rng(rng, alphabet, special_set))
    }

    pub fn generate(&mut self, n: usize) -> SecretSlice<u8> {
        let a = &self.alphabet;
        let rules = &self.rules;
        let rng = &mut self.rng;

        let mut s = vec![0u8; n];
        let mut nextp = 0;
        for rule in rules {
            match &rule {
                Rule::MustInclude(ma) => {
                    let mai = rng.random_range(0..ma.len());
                    s[nextp] = ma[mai];
                    nextp += 1;
                }
            }
        }
        for c in s.iter_mut().skip(nextp) {
            *c = a[rng.random_range(0..a.len())];
        }
        s.shuffle(rng);
        SecretSlice::new(s.into())
    }

    /// Ensures at least one special character is present in the generated
    /// results if present in the alphabet.
    pub fn with_special(self) -> Result<Self, Error> {
        let a: Alphabet = self.special_set.clone().into();
        self.with_rule(Rule::MustInclude(a))
    }

    /// Ensures at least one lowercase letter is present in the generated
    /// results if present in the alphabet.
    pub fn with_lower(self) -> Result<Self, Error> {
        let v: Vec<u8> = (b'a'..=b'z').collect();
        self.with_rule(Rule::MustInclude(v.try_into().unwrap()))
    }

    /// Ensures at least one uppercase letter is present in the generated
    /// results if present in the alphabet.
    pub fn with_upper(self) -> Result<Self, Error> {
        let v: Vec<u8> = (b'A'..=b'Z').collect();
        self.with_rule(Rule::MustInclude(v.try_into().unwrap()))
    }

    /// Ensures at least one digit is present in the generated
    /// results if present in the alphabet.
    pub fn with_digit(self) -> Result<Self, Error> {
        let v: Vec<u8> = (b'0'..=b'9').collect();
        self.with_rule(Rule::MustInclude(v.try_into().unwrap()))
    }

    /// Ensures all generated results follow the specified rules.
    fn with_rule(mut self, rule: Rule) -> Result<Self, Error> {
        let set = &self.alphabet.set;
        match &rule {
            Rule::MustInclude(chars) => {
                let present = chars
                    .as_slice()
                    .iter()
                    .copied()
                    .filter(|&c| set.contains(c))
                    .count();
                if present == 0 {
                    return Err(Error::UnsatisfiableRule);
                }
                if present == chars.len() {
                    self.rules.push(rule);
                } else {
                    let nrc = chars
                        .as_slice()
                        .iter()
                        .copied()
                        .filter(|&c| set.contains(c))
                        .collect::<Vec<u8>>();
                    let nr = Rule::MustInclude(nrc.try_into().unwrap());
                    self.rules.push(nr);
                }
            }
        }
        Ok(self)
    }
}

impl Default for PassGen<ChaCha20Rng> {
    fn default() -> Self {
        Self::new(Alphabet::default(), SpecialSet::Default)
    }
}

impl PassGen<ChaCha20Rng> {
    pub fn new<A>(alphabet: A, special_set: SpecialSet) -> Self
    where
        A: Into<Alphabet>,
    {
        Self::new_with_rng(PassGen::default_rng(), alphabet.into(), special_set)
    }

    pub fn with_alphabet<A>(alphabet: A) -> Result<Self, A::Error>
    where
        A: TryInto<Alphabet>,
    {
        Self::try_new(PassGen::default_rng(), alphabet, SpecialSet::Default)
    }

    pub fn with_rng<R>(rng: R) -> PassGen<R>
    where
        R: CryptoRng,
    {
        PassGen::new_with_rng(rng, Alphabet::default(), SpecialSet::Default)
    }

    fn default_rng() -> ChaCha20Rng {
        // Infallible when seeded from SysRng.
        ChaCha20Rng::try_from_rng(&mut SysRng).unwrap()
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
    fn alphabet_normalizes_duplicates() {
        let a = Alphabet::try_from("aaabbbccc").unwrap();
        assert_eq!(a.as_slice(), b"abc");
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn alphabet_add_deduplicates() {
        let mut a = Alphabet::try_from("abc").unwrap();
        a.add(b"bccdde");
        assert_eq!(a.as_slice(), b"abcde");
    }

    #[test]
    fn alphabet_remove_works() {
        let mut a = Alphabet::try_from("abcdef").unwrap();
        a.remove(b"bdx").unwrap();
        assert_eq!(a.as_slice(), b"acef");
    }

    #[test]
    fn alphabet_remove_forbids_empty_result() {
        let mut a = Alphabet::try_from("abc").unwrap();
        let res = a.remove(b"abc");
        assert!(matches!(res, Err(Error::EmptyAlphabet)));
    }

    #[test]
    fn empty_alphabet_fails() {
        assert!(matches!(Alphabet::try_from(""), Err(Error::EmptyAlphabet)));
    }

    #[test]
    fn duplicate_alphabet_distribution_remains_uniform() {
        let a1 = Alphabet::try_from("abc").unwrap();
        let a2 = Alphabet::try_from("aaabbbccc").unwrap();
        assert_eq!(a1.as_slice(), a2.as_slice());
    }

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
        let alphabet = Alphabet::try_from("abc").unwrap();
        let mut g = PassGen::with_alphabet(alphabet.clone()).unwrap();
        let p = g.generate(8);
        for &c in p.expose_secret() {
            assert!(alphabet.as_slice().contains(&c));
        }
    }

    #[test]
    fn generator_respects_length() {
        let k = 16;
        let mut g = PassGen::with_alphabet("xyz").unwrap();
        let p = g.generate(k);
        assert_eq!(p.expose_secret().len(), k);
    }

    #[test]
    fn generated_chars_are_always_in_alphabet() {
        let alphabet = Alphabet::try_from("abc123").unwrap();
        let mut g = PassGen::with_alphabet(alphabet.clone()).unwrap();
        for _ in 0..1000 {
            let p = g.generate(64);
            for &c in p.expose_secret() {
                assert!(alphabet.as_slice().contains(&c));
            }
        }
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
        let alphabet = Alphabet::try_from("abcdef1234567890").unwrap();
        let mut g = PassGen::new(alphabet.clone(), SpecialSet::Default);

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

    #[test]
    fn zero_length_generation_works() {
        let mut g = PassGen::default();
        let p = g.generate(0);
        assert_eq!(p.expose_secret().len(), 0);
    }
}
