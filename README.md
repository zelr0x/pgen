# pgen
![Tests](https://github.com/zelr0x/pgen/actions/workflows/ci.yml/badge.svg)

Simple secure random password generator

It uses a cryptographically-secure RNG and tries its best to avoid leaving passwords in memory longer than needed.

Generated passwords are random printable ASCII sequences and are not human-readable.


## Defaults
- Default alphabet consists of printable characters except the special characters: only punctuation characters in the alphabet are the underscore and the minus
- Default RNG is ChaCha20


## CLI
Provided CLI tool generates passwords that suit most password requirements and provide high security given reasonable length. The generator uses default RNG.

```sh
pgen 32
```
will output something like
```sh
oYLlkEX7-PM8yVr2C8FejKnjnqNKmGzw
```

It is possible to modify the alphabet or require certain rules to be satisfied. For example, if you need a password that includes at least one lowercase (`-l`), one uppercase (`-u`), one special character (`-s`), and one digit (`-d`) you can use:
```sh
pgen 16 -lusd
```

`-c` is a shorthand for `-lu`, so alternative to the above is:
```sh
pgen 16 -csd
```
The order of those flags doesn't matter.

See help (`-h`|`--help`) for a full list of options.


## Library

Cargo.toml:
```toml
pgen = { git = "https://github.com/zelr0x/pgen", tag = "0.3.0" }
```

Use:
```rust
use pgen::{self, ExposeSecret};
```

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

### Rules
It is possible to require the following rules to be satisfied by all generated passwords with the following methods:
- `with_special` - at least one character from a special set
- `with_lower` - at least one lowercase character
- `with_upper` - at least one uppercase character
- `with_digit` - at least one digit

Default special set includes only underscore and hyphen, other options are:
- `SpecialSet::Full` for the full set of ASCII special characters
- `SpecialSet::Safe` for the "safe" set, which includes all special characters except space, backtick, backslash, single and double quotes, pipe, and angle brackets
- `SpecialSet::Custom` for a custom set
