//! CLI tool for pam_web3 administration
//!
//! Provides utilities for:
//! - Generating machine keypairs (secp256k1 ECIES)
//! - Encrypting machine IDs for NFT minting
//!   - Server field: secp256k1 ECIES
//!   - User field: AES-256-GCM with signature-derived key
//! - Symmetric encryption/decryption with signature-derived keys
//! - Deriving public keys from private keys
//! - Getting x25519 encryption public key for wallet (legacy)

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
        "encrypt" => encrypt_machine_id(&args[2..]),
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
    generate-keypair        Generate a new secp256k1 ECIES keypair for a machine
    encrypt                 Encrypt a machine ID for NFT metadata (server field)
    encrypt-symmetric       Encrypt data with signature-derived AES-256-GCM key
    decrypt-symmetric       Decrypt data with signature-derived AES-256-GCM key
    derive-pubkey           Derive secp256k1 public key from private key
    wallet-encryption-key   Get x25519 encryption public key for a wallet (legacy)
    decrypt                 Decrypt encrypted data (for testing)
    help                    Print this help message

ENCRYPTION SCHEMES:
    Server field (server_encrypted):
        secp256k1 ECIES - decrypted by server using its private key

    User field (user_encrypted):
        AES-256-GCM with signature-derived key
        Key = keccak256(user_signature)
        User signs decrypt_message → same signature → same key → decrypt

EXAMPLES:
    # Generate a new keypair for a machine
    pam_web3_tool generate-keypair --output /etc/pam_web3/server.key

    # Encrypt server field (machine ID for server decryption)
    pam_web3_tool encrypt \
        --machine-id "server-prod-01" \
        --server-pubkey <secp256k1_pubkey_hex>

    # Encrypt user field with signature-derived key
    pam_web3_tool encrypt-symmetric \
        --signature <user_signature_hex> \
        --plaintext '{{"ip":"192.168.1.100","machine_id":"server-01","port":22}}'

    # Decrypt user field with signature-derived key
    pam_web3_tool decrypt-symmetric \
        --signature <user_signature_hex> \
        --ciphertext <hex>

    # Derive secp256k1 public key from private key
    pam_web3_tool derive-pubkey --private-key-file /etc/pam_web3/server.key

    # Decrypt server-encrypted data (for testing)
    pam_web3_tool decrypt --scheme secp256k1 \
        --private-key-file /etc/pam_web3/server.key \
        --ciphertext <hex>
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

fn encrypt_machine_id(args: &[String]) {
    let mut machine_id: Option<String> = None;
    let mut server_pubkey: Option<String> = None;
    let mut user_pubkey: Option<String> = None;
    let mut json_output = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--machine-id" | "-m" => {
                i += 1;
                if i < args.len() {
                    machine_id = Some(args[i].clone());
                }
            }
            "--pubkey" | "--server-pubkey" => {
                i += 1;
                if i < args.len() {
                    server_pubkey = Some(args[i].clone());
                }
            }
            "--user-pubkey" => {
                i += 1;
                if i < args.len() {
                    user_pubkey = Some(args[i].clone());
                }
            }
            "--json" => {
                json_output = true;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let machine_id = machine_id.expect("--machine-id is required");
    let server_pubkey = server_pubkey.expect("--pubkey or --server-pubkey is required");

    // Encrypt for server using secp256k1 ECIES
    let server_pubkey_bytes = hex::decode(&server_pubkey).expect("Invalid server public key hex");
    let server_encrypted =
        ecies::encrypt(&server_pubkey_bytes, &machine_id).expect("Failed to encrypt for server");

    if !json_output {
        println!("Server encrypted (secp256k1 ECIES):");
        println!("{}", server_encrypted);
        println!();
    }

    // Encrypt for user using x25519 (eth_decrypt compatible) if pubkey provided
    let user_encrypted = if let Some(ref user_pubkey) = user_pubkey {
        let user_pubkey_bytes = hex::decode(user_pubkey).expect("Invalid user public key hex");

        if user_pubkey_bytes.len() != 32 {
            eprintln!("User public key must be 32 bytes (x25519). Get it via:");
            eprintln!("  - MetaMask: eth_getEncryptionPublicKey");
            eprintln!("  - This tool: pam_web3_tool wallet-encryption-key --private-key <hex>");
            process::exit(1);
        }

        let encrypted = ecies::encrypt_for_eth_decrypt(&user_pubkey_bytes, &machine_id)
            .expect("Failed to encrypt for user");

        if !json_output {
            println!("User encrypted (x25519-xsalsa20-poly1305, eth_decrypt compatible):");
            println!("{}", encrypted);
            println!();
        }

        Some(encrypted)
    } else {
        if !json_output {
            println!("User encrypted: (not provided, use --user-pubkey to encrypt for user)");
            println!();
        }
        None
    };

    // Output as JSON for easy copying
    if json_output {
        println!(
            r#"{{"server_encrypted":"{}","user_encrypted":"{}"}}"#,
            server_encrypted,
            user_encrypted.unwrap_or_default()
        );
    } else {
        println!("JSON for NFT metadata access field:");
        println!(
            r#"{{
  "server_encrypted": "{}",
  "user_encrypted": "{}"
}}"#,
            server_encrypted,
            user_encrypted.unwrap_or_default()
        );
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
    println!("Use this key as --user-pubkey when encrypting machine IDs.");
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
