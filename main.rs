use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "nxs", about = "Nextsora experimental genesis supply tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create fresh encryption and signing keys. Keep these secret and backed up.
    InitKeys {
        #[arg(long, default_value = "private")]
        dir: PathBuf,
    },
    /// Generate encrypted coin inventory files and a signed manifest.
    Generate {
        #[arg(long, default_value = "genesis")]
        out: PathBuf,
        #[arg(long, default_value_t = 30)]
        files: u32,
        #[arg(long, default_value_t = 1_000_000)]
        coins_per_file: u32,
        #[arg(long, default_value = "private/encryption.key")]
        encryption_key: PathBuf,
        #[arg(long, default_value = "private/signing.key")]
        signing_key: PathBuf,
    },
    /// Verify the manifest signature and every encrypted file checksum.
    Verify {
        #[arg(long, default_value = "genesis")]
        dir: PathBuf,
        #[arg(long, default_value = "private/public.key")]
        public_key: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    network: String,
    ticker: String,
    format_version: u32,
    total_coin_records: u64,
    files: Vec<FileEntry>,
}

#[derive(Serialize, Deserialize)]
struct FileEntry {
    file: String,
    first_coin_number: u64,
    last_coin_number: u64,
    coin_records: u32,
    encrypted_sha256: String,
    encryption: String,
}

fn read_32_byte_key(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("Cannot read key {}: {e}", path.display()))?;
    if bytes.len() != 32 {
        return Err(format!("Key {} must contain exactly 32 raw bytes", path.display()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn init_keys(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut encryption_key = [0u8; 32];
    OsRng.fill_bytes(&mut encryption_key);

    let signing = SigningKey::generate(&mut OsRng);
    fs::write(dir.join("encryption.key"), encryption_key).map_err(|e| e.to_string())?;
    fs::write(dir.join("signing.key"), signing.to_bytes()).map_err(|e| e.to_string())?;
    fs::write(dir.join("public.key"), signing.verifying_key().to_bytes())
        .map_err(|e| e.to_string())?;

    println!("Keys created in {}.", dir.display());
    println!("IMPORTANT: Back up encryption.key and signing.key securely.");
    println!("Never commit the private/ directory or publish private keys.");
    Ok(())
}

fn generate(
    out: &Path,
    file_count: u32,
    coins_per_file: u32,
    encryption_key_path: &Path,
    signing_key_path: &Path,
) -> Result<(), String> {
    if file_count == 0 || coins_per_file == 0 {
        return Err("files and coins-per-file must both be greater than zero".into());
    }

    let encryption_key = read_32_byte_key(encryption_key_path)?;
    let signing_bytes = read_32_byte_key(signing_key_path)?;
    let signing_key = SigningKey::from_bytes(&signing_bytes);
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|_| "Invalid AES-256 key".to_string())?;

    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut entries = Vec::with_capacity(file_count as usize);
    let mut next_number: u64 = 1;

    for file_index in 1..=file_count {
        let file_name = format!("block.{file_index:02}.enc");
        let mut plaintext = Vec::with_capacity(coins_per_file as usize * 80);

        for _ in 0..coins_per_file {
            let mut random_material = [0u8; 32];
            OsRng.fill_bytes(&mut random_material);

            let mut hasher = Sha256::new();
            hasher.update(b"NEXTSORA-NXS-COIN-ID-V1");
            hasher.update(next_number.to_be_bytes());
            hasher.update(random_material);
            let coin_hash = hex::encode(hasher.finalize());

            writeln!(&mut plaintext, "{} {}", next_number, coin_hash)
                .map_err(|e| e.to_string())?;
            next_number += 1;
        }

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| format!("Encryption failed for {file_name}"))?;

        // File format: 12-byte random nonce followed by AES-256-GCM ciphertext/tag.
        let mut output_bytes = Vec::with_capacity(12 + ciphertext.len());
        output_bytes.extend_from_slice(&nonce_bytes);
        output_bytes.extend_from_slice(&ciphertext);

        fs::write(out.join(&file_name), &output_bytes).map_err(|e| e.to_string())?;

        let first = ((file_index as u64 - 1) * coins_per_file as u64) + 1;
        let last = first + coins_per_file as u64 - 1;
        entries.push(FileEntry {
            file: file_name,
            first_coin_number: first,
            last_coin_number: last,
            coin_records: coins_per_file,
            encrypted_sha256: sha256_hex(&output_bytes),
            encryption: "AES-256-GCM".into(),
        });

        println!("Generated block.{file_index:02}.enc ({coins_per_file} records)");
    }

    let manifest = Manifest {
        network: "Nextsora".into(),
        ticker: "NXS".into(),
        format_version: 1,
        total_coin_records: file_count as u64 * coins_per_file as u64,
        files: entries,
    };

    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    let signature = signing_key.sign(&manifest_bytes);

    fs::write(out.join("manifest.json"), &manifest_bytes).map_err(|e| e.to_string())?;
    fs::write(out.join("manifest.sig"), hex::encode(signature.to_bytes()))
        .map_err(|e| e.to_string())?;

    println!("Supply generated: {} coin records.", manifest.total_coin_records);
    println!("Manifest signed. Keep your signing key private.");
    Ok(())
}

fn verify(dir: &Path, public_key_path: &Path) -> Result<(), String> {
    let manifest_bytes = fs::read(dir.join("manifest.json")).map_err(|e| e.to_string())?;
    let signature_hex = fs::read_to_string(dir.join("manifest.sig")).map_err(|e| e.to_string())?;
    let signature_bytes = hex::decode(signature_hex.trim()).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| e.to_string())?;

    let public_bytes = read_32_byte_key(public_key_path)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_bytes).map_err(|e| e.to_string())?;
    verifying_key
        .verify(&manifest_bytes, &signature)
        .map_err(|_| "Manifest signature INVALID".to_string())?;

    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;

    let mut counted: u64 = 0;
    for entry in &manifest.files {
        let bytes = fs::read(dir.join(&entry.file))
            .map_err(|e| format!("Missing or unreadable {}: {e}", entry.file))?;
        let actual = sha256_hex(&bytes);
        if actual != entry.encrypted_sha256 {
            return Err(format!("Checksum mismatch: {}", entry.file));
        }
        counted += entry.coin_records as u64;
        println!("OK: {}", entry.file);
    }

    if counted != manifest.total_coin_records {
        return Err("Manifest total does not match file record counts".into());
    }

    println!(
        "VALID: {} {} coin records; signature and file checksums verified.",
        manifest.total_coin_records, manifest.ticker
    );
    println!("Note: this checks encrypted-file integrity; it does not validate coin ownership or blockchain consensus.");
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::InitKeys { dir } => init_keys(&dir),
        Commands::Generate {
            out,
            files,
            coins_per_file,
            encryption_key,
            signing_key,
        } => generate(&out, files, coins_per_file, &encryption_key, &signing_key),
        Commands::Verify { dir, public_key } => verify(&dir, &public_key),
    };

    if let Err(error) = result {
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }
}
