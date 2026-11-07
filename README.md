# Nextsora (NXS) Genesis Supply — experimental 0.1

This Rust project creates encrypted files containing unique NXS coin-record identifiers and a signed manifest.

## Requirements

- Rust stable toolchain and Cargo
- A trusted, private environment for generating and storing keys
- Enough disk space for the generated inventory

## Quick start

```bash
cargo build --release

# Create keys once. Back up the private keys securely.
cargo run --release -- init-keys

# Start with a small test, not the full supply.
cargo run --release -- generate --out test-genesis --files 1 --coins-per-file 1000

# Verify the generated files.
cargo run --release -- verify --dir test-genesis
```

After testing and reviewing the design, the full proposed supply command is:

```bash
cargo run --release -- generate --out genesis --files 30 --coins-per-file 1000000
cargo run --release -- verify --dir genesis
```

The full generation produces 30 files with 1,000,000 records each (30,000,000 records total). It can require substantial disk space and time.

## File format

Each `block.NN.enc` file is:

- 12-byte random AES-GCM nonce
- AES-256-GCM ciphertext and authentication tag

The plaintext inside each encrypted file has one record per line:

```text
coin_number 64_character_hex_identifier
```

Identifiers are generated using OS-provided cryptographic randomness and SHA-256 with a domain-separation label and sequential record number.

## Security notes

- `private/encryption.key` and `private/signing.key` are secrets. Never upload them to GitHub, a website, or share them with miners.
- `private/public.key` is safe to distribute for signature verification.
- The signed manifest authenticates the file list and encrypted-file checksums.
- SHA-256 checksums detect accidental or malicious file changes when checked against the signed manifest.
- Encryption at rest does **not** make a file uneditable on another person's device. It makes unauthorized changes detectable when authenticated and verified.
- This is an experimental supply-file generator, **not a complete cryptocurrency**. It does not implement wallet ownership, consensus, transaction validation, mining, double-spend prevention, or network synchronization.
- Do not use this for real funds or a public mainnet without independent cryptographic review, protocol design, testing, and security audits.

## Git safety

The `.gitignore` excludes the private key directory and generated supply files by default. Keep private keys in a secure backup location.
