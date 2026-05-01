# pgen
![Tests](https://github.com/zelr0x/pgen/actions/workflows/ci.yml/badge.svg)

Simple secure random password generator

It uses a cryptographically-secure RNG (CRNG) and tries its best to avoid leaving passwords in memory longer than needed.

Generated passwords are not human-readable.


## Defaults
- Default alphabet consists of printable Latin1 characters except the special characters: only punctuation characters in the alphabet are the underscore and the minus
- Default RNG is ChaCha12


## CLI
Provided CLI tool generates passwords that suit most password requirements and provide high security given reasonable length. The generator uses default alphabet and RNG.

```sh
pgen 32
```
will output something like
```sh
oYLlkEX7-PM8yVr2C8FejKnjnqNKmGzw
```


## Library
The provided library allows to specify a different alphabet or a different generator.

If you generate passwords rarely and are ok with default RNG and alphabet you can do this:
```rust
pgen::generate(32);
```

If you need to generate many passwords repeatedly or if you want to use a different RNG or alphabet, use `PassGen` with `PassGen::new`, `Passgen::wtih_rng` or `Passgen::with_alphabet`. For example, to create a generator that can be used repeatedly to generate passwords containing only specified characters you can do this:
```rust
let p = PassGen::with_alphabet("abc")?;
p.generate(5); // cabac
```
