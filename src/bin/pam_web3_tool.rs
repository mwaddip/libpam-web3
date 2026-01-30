//! CLI tool for pam_web3 administration
//!
//! Provides utilities for:
//! - Symmetric encryption/decryption with signature-derived keys (for user_encrypted field)
//! - Generating keypairs for testing
//! - Deriving public keys from private keys
//! - Getting x25519 encryption public key for wallet (legacy)
//!
//! Note: Server-side encryption (serverEncrypted) was removed in v0.4.0.
//! Authentication now uses ownership-based verification (wallet + NFT token ID).

use pam_web3::ecies;
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "generate-keypair" => generate_keypair(&args[2..]),
        "encrypt-symmetric" => encrypt_symmetric(&args[2..]),
        "decrypt-symmetric" => decrypt_symmetric(&args[2..]),
        "derive-pubkey" => derive_public_key(&args[2..]),
        "wallet-encryption-key" => get_wallet_encryption_key(&args[2..]),
        "decrypt" => decrypt_data(&args[2..]),
        "help" | "--help" | "-h" => print_usage(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    println!(
        r#"pam_web3_tool - Administration tool for pam_web3

USAGE:
    pam_web3_tool <COMMAND> [OPTIONS]

COMMANDS:
    generate-keypair        Generate a new secp256k1 keypair (for testing)
    encrypt-symmetric       Encrypt data with signature-derived AES-256-GCM key
    decrypt-symmetric       Decrypt data with signature-derived AES-256-GCM key
    derive-pubkey           Derive secp256k1 public key from private key
    wallet-encryption-key   Get x25519 encryption public key for a wallet (legacy)
    decrypt                 Decrypt encrypted data (for testing)
    help                    Print this help message

AUTHENTICATION MODEL (v0.4.0+):
    Server-side decryption (serverEncrypted) has been removed.
    Authentication now uses:
    1. Wallet ownership (user signs OTP challenge)
    2. NFT ownership (token ID matches GECOS entry in /etc/passwd)

    The user_encrypted field is OPTIONAL and allows users to store
    connection details that only they can decrypt.

ENCRYPTION SCHEME (user_encrypted):
    AES-256-GCM with signature-derived key
    Key = keccak256(user_signature)
    User signs decrypt_message → same signature → same key → decrypt

EXAMPLES:
    # Generate a new keypair (for testing)
    pam_web3_tool generate-keypair

    # Encrypt user field with signature-derived key
    pam_web3_tool encrypt-symmetric \
        --signature <user_signature_hex> \
        --plaintext '{{"hostname":"server.example.com","port":22}}'

    # Decrypt user field with signature-derived key
    pam_web3_tool decrypt-symmetric \
        --signature <user_signature_hex> \
        --ciphertext <hex>

    # Derive secp256k1 public key from private key
    pam_web3_tool derive-pubkey --private-key <hex>
"#
    );
}

fn generate_keypair(args: &[String]) {
    let mut output_path: Option<String> = None;
    let mut show_pubkey = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                if i < args.len() {
                    output_path = Some(args[i].clone());
                }
            }
            "--show-pubkey" => {
                show_pubkey = true;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    // Generate secp256k1 ECIES keypair
    let (private_key_hex, public_key_hex) = ecies::generate_keypair();

    // Output private key
    if let Some(ref path) = output_path {
        fs::write(path, &private_key_hex).expect("Failed to write private key file");
        println!("Private key written to: {}", path);

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms).unwrap();
            println!("Permissions set to 600 (owner read/write only)");
        }
    } else {
        println!("Private key (hex): {}", private_key_hex);
    }

    if show_pubkey || output_path.is_some() {
        println!("Public key (hex):  {}", public_key_hex);
    }
}

fn derive_public_key(args: &[String]) {
    let mut private_key_file: Option<String> = None;
    let mut private_key_hex: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--private-key-file" | "-f" => {
                i += 1;
                if i < args.len() {
                    private_key_file = Some(args[i].clone());
                }
            }
            "--private-key" | "-k" => {
                i += 1;
                if i < args.len() {
                    private_key_hex = Some(args[i].clone());
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let private_key_hex = if let Some(file) = private_key_file {
        fs::read_to_string(&file)
            .expect("Failed to read private key file")
            .trim()
            .to_string()
    } else if let Some(hex) = private_key_hex {
        hex
    } else {
        eprintln!("Either --private-key-file or --private-key is required");
        process::exit(1);
    };

    let private_key_bytes = hex::decode(&private_key_hex).expect("Invalid private key hex");

    let public_key_hex =
        ecies::derive_public_key(&private_key_bytes).expect("Failed to derive public key");

    println!("Public key (secp256k1, hex): {}", public_key_hex);
}

fn get_wallet_encryption_key(args: &[String]) {
    let mut private_key_hex: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--private-key" | "-k" => {
                i += 1;
                if i < args.len() {
                    private_key_hex = Some(args[i].clone());
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let private_key_hex = private_key_hex.expect("--private-key is required");

    // Strip 0x prefix if present
    let private_key_hex = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&private_key_hex);

    let private_key_bytes = hex::decode(private_key_hex).expect("Invalid private key hex");

    if private_key_bytes.len() != 32 {
        eprintln!("Private key must be 32 bytes");
        process::exit(1);
    }

    // Derive x25519 public key (same as eth_getEncryptionPublicKey)
    let x25519_pubkey =
        ecies::derive_x25519_public_key(&private_key_bytes).expect("Failed to derive x25519 key");

    println!("x25519 encryption public key (hex): {}", x25519_pubkey);
    println!();
    println!("This is equivalent to calling eth_getEncryptionPublicKey in MetaMask.");
}

fn decrypt_data(args: &[String]) {
    let mut scheme: Option<String> = None;
    let mut private_key_file: Option<String> = None;
    let mut private_key_hex: Option<String> = None;
    let mut ciphertext: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--scheme" | "-s" => {
                i += 1;
                if i < args.len() {
                    scheme = Some(args[i].clone());
                }
            }
            "--private-key-file" | "-f" => {
                i += 1;
                if i < args.len() {
                    private_key_file = Some(args[i].clone());
                }
            }
            "--private-key" | "-k" => {
                i += 1;
                if i < args.len() {
                    private_key_hex = Some(args[i].clone());
                }
            }
            "--ciphertext" | "-c" => {
                i += 1;
                if i < args.len() {
                    ciphertext = Some(args[i].clone());
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let scheme = scheme.unwrap_or_else(|| "secp256k1".to_string());
    let ciphertext = ciphertext.expect("--ciphertext is required");

    let private_key_hex = if let Some(file) = private_key_file {
        fs::read_to_string(&file)
            .expect("Failed to read private key file")
            .trim()
            .to_string()
    } else if let Some(hex) = private_key_hex {
        hex.strip_prefix("0x").unwrap_or(&hex).to_string()
    } else {
        eprintln!("Either --private-key-file or --private-key is required");
        process::exit(1);
    };

    let private_key_bytes = hex::decode(&private_key_hex).expect("Invalid private key hex");

    let decrypted = match scheme.as_str() {
        "secp256k1" | "ecies" => {
            ecies::decrypt(&private_key_bytes, &ciphertext).expect("Decryption failed")
        }
        "x25519" | "eth_decrypt" | "nacl" => {
            ecies::decrypt_eth_encrypted(&private_key_bytes, &ciphertext)
                .expect("Decryption failed")
        }
        _ => {
            eprintln!(
                "Unknown scheme: {}. Use 'secp256k1' or 'x25519'",
                scheme
            );
            process::exit(1);
        }
    };

    println!("Decrypted: {}", decrypted);
}

fn encrypt_symmetric(args: &[String]) {
    let mut signature: Option<String> = None;
    let mut plaintext: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--signature" | "-s" => {
                i += 1;
                if i < args.len() {
                    signature = Some(args[i].clone());
                }
            }
            "--plaintext" | "-p" => {
                i += 1;
                if i < args.len() {
                    plaintext = Some(args[i].clone());
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let signature = signature.expect("--signature is required");
    let plaintext = plaintext.expect("--plaintext is required");

    let ciphertext =
        ecies::encrypt_symmetric_hex(&signature, &plaintext).expect("Encryption failed");

    println!("Ciphertext (hex): {}", ciphertext);
    println!();
    println!("Use this value for the user_encrypted field in the NFT.");
}

fn decrypt_symmetric(args: &[String]) {
    let mut signature: Option<String> = None;
    let mut ciphertext: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--signature" | "-s" => {
                i += 1;
                if i < args.len() {
                    signature = Some(args[i].clone());
                }
            }
            "--ciphertext" | "-c" => {
                i += 1;
                if i < args.len() {
                    ciphertext = Some(args[i].clone());
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let signature = signature.expect("--signature is required");
    let ciphertext = ciphertext.expect("--ciphertext is required");

    let plaintext =
        ecies::decrypt_symmetric_hex(&signature, &ciphertext).expect("Decryption failed");

    println!("Decrypted: {}", plaintext);
}
