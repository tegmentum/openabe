//! OpenABE-RABE CLI - Command line interface for ABE operations

use openabe_rabe::{bsw, ac17_cp, MasterPublicKey, MasterSecretKey, UserSecretKey, Ciphertext};
use std::fs;
use std::io::{self, Read, Write};

fn print_usage() {
    eprintln!(r#"OpenABE-RABE CLI - Attribute Based Encryption

USAGE:
    openabe-rabe-cli <COMMAND> [OPTIONS]

COMMANDS:
    setup       Generate master public and secret keys
    keygen      Generate a user secret key
    encrypt     Encrypt a file or message
    decrypt     Decrypt a file or message
    test        Run a quick roundtrip test

EXAMPLES:
    # Generate keys (BSW CP-ABE)
    openabe-rabe-cli setup --scheme bsw --mpk mpk.json --msk msk.json

    # Generate user key with attributes
    openabe-rabe-cli keygen --scheme bsw --mpk mpk.json --msk msk.json \
        --attrs "role:admin,dept:eng" --sk user.key

    # Encrypt a file
    openabe-rabe-cli encrypt --scheme bsw --mpk mpk.json \
        --policy "role:admin" --input secret.txt --output secret.enc

    # Decrypt a file
    openabe-rabe-cli decrypt --scheme bsw --sk user.key \
        --input secret.enc --output decrypted.txt

    # Run roundtrip test
    openabe-rabe-cli test --scheme bsw
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
        "test" => cmd_test(&args[2..]),
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
    let scheme = parse_arg(args, "--scheme").unwrap_or_else(|| "bsw".to_string());
    let mpk_path = parse_arg(args, "--mpk").unwrap_or_else(|| "mpk.json".to_string());
    let msk_path = parse_arg(args, "--msk").unwrap_or_else(|| "msk.json".to_string());

    println!("Generating {} master keys...", scheme.to_uppercase());

    let (mpk, msk) = match scheme.as_str() {
        "bsw" => bsw::setup().map_err(|e| e.to_string())?,
        "ac17" => ac17_cp::setup().map_err(|e| e.to_string())?,
        _ => return Err(format!("Unknown scheme: {}. Use 'bsw' or 'ac17'", scheme)),
    };

    let mpk_json = serde_json::to_string_pretty(&mpk).map_err(|e| e.to_string())?;
    let msk_json = serde_json::to_string_pretty(&msk).map_err(|e| e.to_string())?;

    fs::write(&mpk_path, mpk_json).map_err(|e| format!("Failed to write MPK: {}", e))?;
    fs::write(&msk_path, msk_json).map_err(|e| format!("Failed to write MSK: {}", e))?;

    println!("Master Public Key written to: {}", mpk_path);
    println!("Master Secret Key written to: {}", msk_path);
    println!("Setup complete!");

    Ok(())
}

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let scheme = parse_arg(args, "--scheme").unwrap_or_else(|| "bsw".to_string());
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

    println!("Generating {} user key for attributes: {:?}", scheme.to_uppercase(), attributes);

    let sk = match scheme.as_str() {
        "bsw" => bsw::keygen(&mpk, &msk, &attributes).map_err(|e| e.to_string())?,
        "ac17" => ac17_cp::keygen(&mpk, &msk, &attributes).map_err(|e| e.to_string())?,
        _ => return Err(format!("Unknown scheme: {}", scheme)),
    };

    let sk_json = serde_json::to_string_pretty(&sk).map_err(|e| e.to_string())?;
    fs::write(&sk_path, sk_json).map_err(|e| format!("Failed to write SK: {}", e))?;

    println!("User Secret Key written to: {}", sk_path);
    println!("Keygen complete!");

    Ok(())
}

fn cmd_encrypt(args: &[String]) -> Result<(), String> {
    let scheme = parse_arg(args, "--scheme").unwrap_or_else(|| "bsw".to_string());
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

    println!("Encrypting with {} under policy: {}", scheme.to_uppercase(), policy);

    let ct = match scheme.as_str() {
        "bsw" => bsw::encrypt(&mpk, &policy, &plaintext).map_err(|e| e.to_string())?,
        "ac17" => ac17_cp::encrypt(&mpk, &policy, &plaintext).map_err(|e| e.to_string())?,
        _ => return Err(format!("Unknown scheme: {}", scheme)),
    };

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
    let scheme = parse_arg(args, "--scheme").unwrap_or_else(|| "bsw".to_string());
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

    println!("Decrypting with {} ...", scheme.to_uppercase());

    let plaintext = match scheme.as_str() {
        "bsw" => bsw::decrypt(&sk, &ct).map_err(|e| e.to_string())?,
        "ac17" => ac17_cp::decrypt(&sk, &ct).map_err(|e| e.to_string())?,
        _ => return Err(format!("Unknown scheme: {}", scheme)),
    };

    // Write plaintext to file or stdout
    if let Some(path) = output_path {
        fs::write(&path, &plaintext).map_err(|e| format!("Failed to write output: {}", e))?;
        println!("Plaintext written to: {}", path);
    } else {
        // Try to print as UTF-8 text
        match String::from_utf8(plaintext.clone()) {
            Ok(text) => println!("{}", text),
            Err(_) => {
                // Print as hex if not valid UTF-8
                println!("(binary data, {} bytes)", plaintext.len());
            }
        }
    }

    println!("Decryption complete!");

    Ok(())
}

fn cmd_test(args: &[String]) -> Result<(), String> {
    let scheme = parse_arg(args, "--scheme").unwrap_or_else(|| "bsw".to_string());

    println!("Running {} roundtrip test...", scheme.to_uppercase());
    println!();

    match scheme.as_str() {
        "bsw" => test_bsw()?,
        "ac17" => test_ac17()?,
        "all" => {
            test_bsw()?;
            println!();
            test_ac17()?;
        }
        _ => return Err(format!("Unknown scheme: {}. Use 'bsw', 'ac17', or 'all'", scheme)),
    }

    Ok(())
}

fn test_bsw() -> Result<(), String> {
    println!("=== BSW CP-ABE Test ===");

    // Setup
    print!("1. Setup... ");
    let (mpk, msk) = bsw::setup().map_err(|e| e.to_string())?;
    println!("OK");

    // Keygen
    print!("2. Keygen (attrs: role:admin, dept:eng)... ");
    let attributes = vec!["role:admin".to_string(), "dept:eng".to_string()];
    let sk = bsw::keygen(&mpk, &msk, &attributes).map_err(|e| e.to_string())?;
    println!("OK");

    // Encrypt (RABE requires quoted attribute names in HumanPolicy format)
    print!("3. Encrypt (policy: \"role:admin\" and \"dept:eng\")... ");
    let policy = r#""role:admin" and "dept:eng""#;
    let plaintext = b"Hello, ABE World! This is a test message.";
    let ct = bsw::encrypt(&mpk, policy, plaintext).map_err(|e| e.to_string())?;
    println!("OK");

    // Decrypt
    print!("4. Decrypt... ");
    let decrypted = bsw::decrypt(&sk, &ct).map_err(|e| e.to_string())?;
    if decrypted != plaintext {
        return Err("Decrypted data doesn't match!".to_string());
    }
    println!("OK");

    println!("5. Verify plaintext: \"{}\"", String::from_utf8_lossy(&decrypted));
    println!();
    println!("BSW CP-ABE test PASSED!");

    Ok(())
}

fn test_ac17() -> Result<(), String> {
    println!("=== AC17 CP-ABE Test ===");

    // Setup
    print!("1. Setup... ");
    let (mpk, msk) = ac17_cp::setup().map_err(|e| e.to_string())?;
    println!("OK");

    // Keygen
    print!("2. Keygen (attrs: A, B, C)... ");
    let attributes = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let sk = ac17_cp::keygen(&mpk, &msk, &attributes).map_err(|e| e.to_string())?;
    println!("OK");

    // Encrypt (RABE requires quoted attribute names in HumanPolicy format)
    print!("3. Encrypt (policy: \"A\" and \"B\")... ");
    let policy = r#""A" and "B""#;
    let plaintext = b"AC17 scheme test message!";
    let ct = ac17_cp::encrypt(&mpk, policy, plaintext).map_err(|e| e.to_string())?;
    println!("OK");

    // Decrypt
    print!("4. Decrypt... ");
    let decrypted = ac17_cp::decrypt(&sk, &ct).map_err(|e| e.to_string())?;
    if decrypted != plaintext {
        return Err("Decrypted data doesn't match!".to_string());
    }
    println!("OK");

    println!("5. Verify plaintext: \"{}\"", String::from_utf8_lossy(&decrypted));
    println!();
    println!("AC17 CP-ABE test PASSED!");

    Ok(())
}
