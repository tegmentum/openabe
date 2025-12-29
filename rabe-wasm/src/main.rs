//! OpenABE-RABE CLI - Command line interface for ABE operations (BLS12-381)

use openabe_rabe::{bsw_cp, MasterPublicKey, MasterSecretKey, UserSecretKey, Ciphertext};
use std::fs;
use std::io::{self, Read};

fn print_usage() {
    eprintln!(r#"OpenABE-RABE CLI - Attribute Based Encryption (BLS12-381)

USAGE:
    openabe-rabe-cli <COMMAND> [OPTIONS]

COMMANDS:
    setup       Generate master public and secret keys
    keygen      Generate a user secret key
    encrypt     Encrypt a file or message
    decrypt     Decrypt a file or message
    test        Run a quick roundtrip test

EXAMPLES:
    # Generate keys (BSW CP-ABE with BLS12-381)
    openabe-rabe-cli setup --mpk mpk.json --msk msk.json

    # Generate user key with attributes
    openabe-rabe-cli keygen --mpk mpk.json --msk msk.json \
        --attrs "admin,dept:eng" --sk user.key

    # Encrypt a file (policy is comma-separated AND of attributes)
    openabe-rabe-cli encrypt --mpk mpk.json \
        --policy "admin" --input secret.txt --output secret.enc

    # Decrypt a file
    openabe-rabe-cli decrypt --sk user.key \
        --input secret.enc --output decrypted.txt

    # Run roundtrip test
    openabe-rabe-cli test
"#);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let result = match args[1].as_str() {
        "setup" => cmd_setup(&args[2..]),
        "keygen" => cmd_keygen(&args[2..]),
        "encrypt" => cmd_encrypt(&args[2..]),
        "decrypt" => cmd_decrypt(&args[2..]),
        "test" => cmd_test(),
        "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn cmd_setup(args: &[String]) -> Result<(), String> {
    let mpk_path = parse_arg(args, "--mpk").unwrap_or_else(|| "mpk.json".to_string());
    let msk_path = parse_arg(args, "--msk").unwrap_or_else(|| "msk.json".to_string());

    println!("Generating BSW CP-ABE master keys (BLS12-381)...");

    let (mpk, msk) = bsw_cp::setup().map_err(|e| e.to_string())?;

    let mpk_json = serde_json::to_string_pretty(&mpk).map_err(|e| e.to_string())?;
    let msk_json = serde_json::to_string_pretty(&msk).map_err(|e| e.to_string())?;

    fs::write(&mpk_path, mpk_json).map_err(|e| format!("Failed to write MPK: {}", e))?;
    fs::write(&msk_path, msk_json).map_err(|e| format!("Failed to write MSK: {}", e))?;

    println!("Master Public Key written to: {}", mpk_path);
    println!("Master Secret Key written to: {}", msk_path);
    println!("Curve: BLS12-381 (128-bit security)");
    println!("Setup complete!");

    Ok(())
}

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let mpk_path = parse_arg(args, "--mpk").ok_or("Missing --mpk argument")?;
    let msk_path = parse_arg(args, "--msk").ok_or("Missing --msk argument")?;
    let attrs_str = parse_arg(args, "--attrs").ok_or("Missing --attrs argument")?;
    let sk_path = parse_arg(args, "--sk").unwrap_or_else(|| "user.key".to_string());

    let mpk_json = fs::read_to_string(&mpk_path)
        .map_err(|e| format!("Failed to read MPK: {}", e))?;
    let msk_json = fs::read_to_string(&msk_path)
        .map_err(|e| format!("Failed to read MSK: {}", e))?;

    let mpk: MasterPublicKey = serde_json::from_str(&mpk_json)
        .map_err(|e| format!("Invalid MPK: {}", e))?;
    let msk: MasterSecretKey = serde_json::from_str(&msk_json)
        .map_err(|e| format!("Invalid MSK: {}", e))?;

    let attributes: Vec<String> = attrs_str.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    println!("Generating user key for attributes: {:?}", attributes);

    let sk = bsw_cp::keygen(&mpk, &msk, &attributes).map_err(|e| e.to_string())?;

    let sk_json = serde_json::to_string_pretty(&sk).map_err(|e| e.to_string())?;
    fs::write(&sk_path, sk_json).map_err(|e| format!("Failed to write SK: {}", e))?;

    println!("User Secret Key written to: {}", sk_path);
    println!("Keygen complete!");

    Ok(())
}

fn cmd_encrypt(args: &[String]) -> Result<(), String> {
    let mpk_path = parse_arg(args, "--mpk").ok_or("Missing --mpk argument")?;
    let policy = parse_arg(args, "--policy").ok_or("Missing --policy argument")?;
    let input_path = parse_arg(args, "--input");
    let output_path = parse_arg(args, "--output");

    let mpk_json = fs::read_to_string(&mpk_path)
        .map_err(|e| format!("Failed to read MPK: {}", e))?;
    let mpk: MasterPublicKey = serde_json::from_str(&mpk_json)
        .map_err(|e| format!("Invalid MPK: {}", e))?;

    // Read plaintext from file or stdin
    let plaintext = if let Some(path) = input_path {
        fs::read(&path).map_err(|e| format!("Failed to read input: {}", e))?
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to read stdin: {}", e))?;
        buffer
    };

    println!("Encrypting with policy: {}", policy);

    let ct = bsw_cp::encrypt(&mpk, &policy, &plaintext).map_err(|e| e.to_string())?;

    let ct_json = serde_json::to_string_pretty(&ct).map_err(|e| e.to_string())?;

    // Write ciphertext to file or stdout
    if let Some(path) = output_path {
        fs::write(&path, ct_json).map_err(|e| format!("Failed to write output: {}", e))?;
        println!("Ciphertext written to: {}", path);
    } else {
        println!("{}", ct_json);
    }

    println!("Encryption complete!");

    Ok(())
}

fn cmd_decrypt(args: &[String]) -> Result<(), String> {
    let sk_path = parse_arg(args, "--sk").ok_or("Missing --sk argument")?;
    let input_path = parse_arg(args, "--input");
    let output_path = parse_arg(args, "--output");

    let sk_json = fs::read_to_string(&sk_path)
        .map_err(|e| format!("Failed to read SK: {}", e))?;
    let sk: UserSecretKey = serde_json::from_str(&sk_json)
        .map_err(|e| format!("Invalid SK: {}", e))?;

    // Read ciphertext from file or stdin
    let ct_json = if let Some(path) = input_path {
        fs::read_to_string(&path).map_err(|e| format!("Failed to read input: {}", e))?
    } else {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)
            .map_err(|e| format!("Failed to read stdin: {}", e))?;
        buffer
    };

    let ct: Ciphertext = serde_json::from_str(&ct_json)
        .map_err(|e| format!("Invalid ciphertext: {}", e))?;

    println!("Decrypting...");

    let plaintext = bsw_cp::decrypt(&sk, &ct).map_err(|e| e.to_string())?;

    // Write plaintext to file or stdout
    if let Some(path) = output_path {
        fs::write(&path, &plaintext).map_err(|e| format!("Failed to write output: {}", e))?;
        println!("Plaintext written to: {}", path);
    } else {
        // Try to print as UTF-8 text
        match String::from_utf8(plaintext.clone()) {
            Ok(text) => println!("{}", text),
            Err(_) => {
                println!("(binary data, {} bytes)", plaintext.len());
            }
        }
    }

    println!("Decryption complete!");

    Ok(())
}

fn cmd_test() -> Result<(), String> {
    println!("=== BSW CP-ABE Test (BLS12-381) ===");
    println!();

    // Setup
    print!("1. Setup... ");
    let (mpk, msk) = bsw_cp::setup().map_err(|e| e.to_string())?;
    println!("OK");

    // Keygen
    print!("2. Keygen (attrs: admin, dept:eng)... ");
    let attributes = vec!["admin".to_string(), "dept:eng".to_string()];
    let sk = bsw_cp::keygen(&mpk, &msk, &attributes).map_err(|e| e.to_string())?;
    println!("OK");

    // Encrypt (policy is comma-separated for AND)
    print!("3. Encrypt (policy: admin, dept:eng)... ");
    let policy = "admin, dept:eng";
    let plaintext = b"Hello, BLS12-381 ABE World! This is a secure message.";
    let ct = bsw_cp::encrypt(&mpk, policy, plaintext).map_err(|e| e.to_string())?;
    println!("OK");

    // Decrypt
    print!("4. Decrypt... ");
    let decrypted = bsw_cp::decrypt(&sk, &ct).map_err(|e| e.to_string())?;
    if decrypted != plaintext {
        return Err("Decrypted data doesn't match!".to_string());
    }
    println!("OK");

    println!("5. Verify plaintext: \"{}\"", String::from_utf8_lossy(&decrypted));
    println!();
    println!("BSW CP-ABE (BLS12-381) test PASSED!");
    println!();
    println!("Curve: BLS12-381 (128-bit security level)");

    Ok(())
}
