
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::PathBuf,
};

#[derive(Parser)]
#[command(name = "nextsora")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    InitKeys,
    Generate {
        #[arg(long, default_value_t = 1)]
        files: u32,
        #[arg(long, default_value_t = 1000)]
        coins_per_file: u32,
    },
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    network: String,
    ticker: String,
    total_supply: u64,
    files: Vec<FileRecord>,
}

#[derive(Serialize, Deserialize)]
struct FileRecord {
    filename: String,
    coin_count: u32,
    sha256: String,
}

fn hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn init_keys() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("private")?;

    let mut encryption_key = [0u8; 32];
    OsRng.fill_bytes(&mut encryption_key);

    let signing_key = SigningKey::generate(&mut OsRng);

    fs::write("private/encryption.key", encryption_key)?;
    fs::write("private/signing.key", signing_key.to_bytes())?;
    fs::write(
        "private/public.key",
        signing_key.verifying_key().to_bytes(),
    )?;

    println!("Nextsora security keys generated.");
    println!("Keep private keys secret.");

    Ok(())
}

fn generate(
    file_count: u32,
    coins_per_file: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption_key = fs::read("private/encryption.key")?;
    let signing_bytes = fs::read("private/signing.key")?;

    let signing_array: [u8; 32] = signing_bytes.try_into()
        .map_err(|_| "Invalid signing key")?;

    let signing_key = SigningKey::from_bytes(&signing_array);

    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    fs::create_dir_all("genesis")?;

    let mut records = Vec::new();
    let mut coin_number = 1u64;

    for file_index in 1..=file_count {
        let filename = format!("block.{:02}.enc", file_index);
        let mut plaintext = Vec::new();

        for _ in 0..coins_per_file {
            let mut random = [0u8; 32];
            OsRng.fill_bytes(&mut random);

            let mut hasher = Sha256::new();
            hasher.update(b"NEXTSORA-NXS-COIN-V1");
            hasher.update(coin_number.to_be_bytes());
            hasher.update(random);

            let coin_hash = hex::encode(hasher.finalize());

            writeln!(
                &mut plaintext,
                "{} {}",
                coin_number,
                coin_hash
            )?;

            coin_number += 1;
        }

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref())?;

        let mut output = nonce_bytes.to_vec();
        output.extend_from_slice(&encrypted);

        fs::write(
            PathBuf::from("genesis").join(&filename),
            &output,
        )?;

        records.push(FileRecord {
            filename,
            coin_count: coins_per_file,
            sha256: hash(&output),
        });

        println!("Generated block.{:02}.enc", file_index);
    }

    let manifest = Manifest {
        network: "Nextsora".into(),
        ticker: "NXS".into(),
        total_supply: file_count as u64 * coins_per_file as u64,
        files: records,
    };

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

    let signature = signing_key.sign(&manifest_bytes);

    fs::write("genesis/manifest.json", &manifest_bytes)?;
    fs::write(
        "genesis/manifest.sig",
        hex::encode(signature.to_bytes()),
    )?;

    println!("------------------------------");
    println!("NEXTSORA SUPPLY GENERATED");
    println!("Total coins: {}", manifest.total_supply);
    println!("Files: {}", file_count);
    println!("------------------------------");

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::InitKeys => init_keys(),
        Commands::Generate {
            files,
            coins_per_file,
        } => generate(files, coins_per_file),
    };

    if let Err(error) = result {
        eprintln!("ERROR: {}", error);
        std::process::exit(1);
    }
}
