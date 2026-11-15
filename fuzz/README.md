# aegis-fuzz

These are cargo-fuzz (libFuzzer) targets for `aegis-core`. The crate has its
own `[workspace]`, so the main workspace never builds it.

| Target                | What it feeds                         | Property                                                        |
|-----------------------|---------------------------------------|-----------------------------------------------------------------|
| `vault_open`          | arbitrary bytes as a vault file       | no panic, hang or OOM in `format::open` (with and without a keyfile), `parse_header_v2`, `read_salt`, `legacy_attempts` |
| `vault_json`          | arbitrary bytes as decrypted JSON     | no panic; anything that parses must round-trip through `to_json` to an equal `serde_json::Value` |
| `seal_open_roundtrip` | arbitrary password, keyfile, salt, plaintext | `seal` followed by `open_v2`/`open` gives back the exact plaintext, key, salt and params; a 1-bit corruption is rejected |

Argon2 would dominate every run at real costs, so the targets keep it cheap:

* `vault_open` rewrites in-range costs in a v2 header to tiny valid ones
  (`m` from 8 to 47 KiB, `t` of 1 or 2, `p` of 1 or 2). Out-of-range costs are
  left alone so that validation still gets fuzzed.
* Files without the `AEGS` magic would run Argon2 at fixed legacy costs of
  19 to 64 MiB. For those inputs, only the pure layout parsing is fuzzed.

## Running

You need a nightly toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz

cd fuzz
# Optional seed corpus: the compatibility fixtures.
mkdir -p corpus/vault_open corpus/vault_json
cp ../aegis-core/tests/fixtures/*.aegis corpus/vault_open/
cp ../aegis-core/tests/fixtures/expected.json corpus/vault_json/

cargo +nightly fuzz run vault_open          -- -max_total_time=90
cargo +nightly fuzz run vault_json          -- -max_total_time=90
cargo +nightly fuzz run seal_open_roundtrip -- -max_total_time=90
```

Crashes are written to `artifacts/<target>/`. To replay one:

```sh
cargo +nightly fuzz run vault_json artifacts/vault_json/crash-<hash>
```

`target/`, `corpus/`, `artifacts/` and `coverage/` are git-ignored.

On NixOS, run these commands inside a shell that provides rustup's nightly
toolchain. cargo-fuzz also needs a C compiler to build libFuzzer.

A stable-Rust subset of these checks runs in normal CI as
`aegis-core/tests/robustness.rs`.
