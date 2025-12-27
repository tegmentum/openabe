//! RABE CLI - Command-line interface for Attribute-Based Encryption
//!
//! Supports:
//! - Waters '11 CP-ABE (CPA and CCA security)
//! - GPSW KP-ABE
//! - AC17 CP-ABE
//! - DABE (Decentralized Multi-Authority ABE)

use clap::{Parser, Subcommand, ValueEnum};
use rand::thread_rng;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use rabe_abe::cbor;
use rabe_abe::lsss::PolicyNode;
use rabe_abe::schemes::{
    waters, waters_cca, gpsw, ac17, dabe,
};

/// RABE CLI - Attribute-Based Encryption
#[derive(Parser)]
#[command(name = "rabe-cli")]
#[command(about = "Attribute-Based Encryption CLI supporting multiple schemes")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate master public and secret keys
    Setup {
        /// ABE scheme to use
        #[arg(short, long, value_enum, default_value = "waters")]
        scheme: Scheme,

        /// Output file for master public key
        #[arg(short = 'p', long, default_value = "mpk.cbor")]
        mpk_file: PathBuf,

        /// Output file for master secret key
        #[arg(short = 'm', long, default_value = "msk.cbor")]
        msk_file: PathBuf,
    },

    /// Generate a user secret key
    Keygen {
        /// ABE scheme to use
        #[arg(short, long, value_enum, default_value = "waters")]
        scheme: Scheme,

        /// Master public key file
        #[arg(short = 'p', long, default_value = "mpk.cbor")]
        mpk_file: PathBuf,

        /// Master secret key file
        #[arg(short = 'm', long, default_value = "msk.cbor")]
        msk_file: PathBuf,

        /// Output file for user secret key
        #[arg(short = 'o', long, default_value = "sk.cbor")]
        sk_file: PathBuf,

        /// For CP-ABE: comma-separated list of attributes (e.g., "admin,developer")
        /// For KP-ABE: policy string (e.g., "(admin AND developer)")
        #[arg(short = 'a', long)]
        attrs_or_policy: String,
    },

    /// Encrypt a file
    Encrypt {
        /// ABE scheme to use
        #[arg(short, long, value_enum, default_value = "waters")]
        scheme: Scheme,

        /// Master public key file
        #[arg(short = 'p', long, default_value = "mpk.cbor")]
        mpk_file: PathBuf,

        /// For CP-ABE: policy string (e.g., "(admin AND developer)")
        /// For KP-ABE: comma-separated list of attributes
        #[arg(short = 'a', long)]
        policy_or_attrs: String,

        /// Input plaintext file
        #[arg(short = 'i', long)]
        input: PathBuf,

        /// Output ciphertext file
        #[arg(short = 'o', long)]
        output: PathBuf,
    },

    /// Decrypt a file
    Decrypt {
        /// ABE scheme to use
        #[arg(short, long, value_enum, default_value = "waters")]
        scheme: Scheme,

        /// Master public key file
        #[arg(short = 'p', long, default_value = "mpk.cbor")]
        mpk_file: PathBuf,

        /// User secret key file
        #[arg(short = 'k', long, default_value = "sk.cbor")]
        sk_file: PathBuf,

        /// Input ciphertext file
        #[arg(short = 'i', long)]
        input: PathBuf,

        /// Output plaintext file
        #[arg(short = 'o', long)]
        output: PathBuf,
    },

    // =========================================================================
    // DABE (Decentralized Multi-Authority ABE) Commands
    // =========================================================================

    /// [DABE] Generate global parameters shared by all authorities
    DabeGlobalSetup {
        /// Output file for global parameters
        #[arg(short = 'g', long, default_value = "dabe_gp.json")]
        gp_file: PathBuf,
    },

    /// [DABE] Create a new authority with its own key pair
    DabeAuthSetup {
        /// Global parameters file
        #[arg(short = 'g', long, default_value = "dabe_gp.json")]
        gp_file: PathBuf,

        /// Authority ID (unique identifier for this authority)
        #[arg(short = 'a', long)]
        authority_id: String,

        /// Output file for authority public key
        #[arg(short = 'p', long)]
        apk_file: PathBuf,

        /// Output file for authority secret key
        #[arg(short = 's', long)]
        ask_file: PathBuf,
    },

    /// [DABE] Authority issues key component to a user for specific attributes
    DabeAuthKeygen {
        /// Global parameters file
        #[arg(short = 'g', long, default_value = "dabe_gp.json")]
        gp_file: PathBuf,

        /// Authority secret key file
        #[arg(short = 's', long)]
        ask_file: PathBuf,

        /// User's global ID (e.g., email address)
        #[arg(short = 'u', long)]
        user_gid: String,

        /// Comma-separated list of attributes to issue (without authority prefix)
        #[arg(short = 'a', long)]
        attrs: String,

        /// Output file for user key component
        #[arg(short = 'o', long)]
        ukc_file: PathBuf,
    },

    /// [DABE] Aggregate key components from multiple authorities into a user secret key
    DabeAggregate {
        /// User's global ID
        #[arg(short = 'u', long)]
        user_gid: String,

        /// Comma-separated list of user key component files
        #[arg(short = 'c', long)]
        ukc_files: String,

        /// Output file for aggregated user secret key
        #[arg(short = 'o', long, default_value = "dabe_usk.json")]
        usk_file: PathBuf,
    },

    /// [DABE] Encrypt a file with a policy using multiple authority public keys
    DabeEncrypt {
        /// Global parameters file
        #[arg(short = 'g', long, default_value = "dabe_gp.json")]
        gp_file: PathBuf,

        /// Comma-separated list of authority public key files
        #[arg(short = 'p', long)]
        apk_files: String,

        /// Policy string with namespaced attributes (e.g., "(auth1:admin AND auth2:manager)")
        #[arg(short = 'a', long)]
        policy: String,

        /// Input plaintext file
        #[arg(short = 'i', long)]
        input: PathBuf,

        /// Output ciphertext file
        #[arg(short = 'o', long)]
        output: PathBuf,
    },

    /// [DABE] Decrypt a file using aggregated user secret key
    DabeDecrypt {
        /// Global parameters file
        #[arg(short = 'g', long, default_value = "dabe_gp.json")]
        gp_file: PathBuf,

        /// User secret key file
        #[arg(short = 'k', long, default_value = "dabe_usk.json")]
        usk_file: PathBuf,

        /// Input ciphertext file
        #[arg(short = 'i', long)]
        input: PathBuf,

        /// Output plaintext file
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
}

#[derive(Clone, ValueEnum)]
enum Scheme {
    /// Waters '11 CP-ABE (CPA security)
    Waters,
    /// Waters '11 CP-ABE with CCA security
    WatersCca,
    /// GPSW KP-ABE
    Gpsw,
    /// AC17 CP-ABE
    Ac17,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Setup { scheme, mpk_file, msk_file } => {
            do_setup(scheme, &mpk_file, &msk_file)
        }
        Commands::Keygen { scheme, mpk_file, msk_file, sk_file, attrs_or_policy } => {
            do_keygen(scheme, &mpk_file, &msk_file, &sk_file, &attrs_or_policy)
        }
        Commands::Encrypt { scheme, mpk_file, policy_or_attrs, input, output } => {
            do_encrypt(scheme, &mpk_file, &policy_or_attrs, &input, &output)
        }
        Commands::Decrypt { scheme, mpk_file, sk_file, input, output } => {
            do_decrypt(scheme, &mpk_file, &sk_file, &input, &output)
        }
        // DABE commands
        Commands::DabeGlobalSetup { gp_file } => {
            do_dabe_global_setup(&gp_file)
        }
        Commands::DabeAuthSetup { gp_file, authority_id, apk_file, ask_file } => {
            do_dabe_auth_setup(&gp_file, &authority_id, &apk_file, &ask_file)
        }
        Commands::DabeAuthKeygen { gp_file, ask_file, user_gid, attrs, ukc_file } => {
            do_dabe_auth_keygen(&gp_file, &ask_file, &user_gid, &attrs, &ukc_file)
        }
        Commands::DabeAggregate { user_gid, ukc_files, usk_file } => {
            do_dabe_aggregate(&user_gid, &ukc_files, &usk_file)
        }
        Commands::DabeEncrypt { gp_file, apk_files, policy, input, output } => {
            do_dabe_encrypt(&gp_file, &apk_files, &policy, &input, &output)
        }
        Commands::DabeDecrypt { gp_file, usk_file, input, output } => {
            do_dabe_decrypt(&gp_file, &usk_file, &input, &output)
        }
    }
}

fn do_setup(scheme: Scheme, mpk_file: &PathBuf, msk_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    match scheme {
        Scheme::Waters | Scheme::WatersCca => {
            let (mpk, msk) = waters::setup(&mut rng);
            let mpk_cbor = cbor::encode_mpk(&mpk)?;
            let msk_cbor = cbor::encode_msk(&msk)?;
            fs::write(mpk_file, &mpk_cbor)?;
            fs::write(msk_file, &msk_cbor)?;
            println!("Waters '11 keys generated:");
        }
        Scheme::Gpsw => {
            let (mpk, msk) = gpsw::setup(&mut rng);
            let mpk_cbor = cbor::encode_gpsw_mpk(&mpk)?;
            let msk_cbor = cbor::encode_gpsw_msk(&msk)?;
            fs::write(mpk_file, &mpk_cbor)?;
            fs::write(msk_file, &msk_cbor)?;
            println!("GPSW KP-ABE keys generated:");
        }
        Scheme::Ac17 => {
            let (mpk, msk) = ac17::setup(&mut rng);
            // For simplicity, use JSON serialization for AC17 (CBOR not implemented yet)
            let mpk_json = serde_json::to_vec(&mpk)?;
            let msk_json = serde_json::to_vec(&msk)?;
            fs::write(mpk_file, &mpk_json)?;
            fs::write(msk_file, &msk_json)?;
            println!("AC17 CP-ABE keys generated:");
        }
    }

    println!("  MPK: {} ({} bytes)", mpk_file.display(), fs::metadata(mpk_file)?.len());
    println!("  MSK: {} ({} bytes)", msk_file.display(), fs::metadata(msk_file)?.len());
    Ok(())
}

fn do_keygen(
    scheme: Scheme,
    mpk_file: &PathBuf,
    msk_file: &PathBuf,
    sk_file: &PathBuf,
    attrs_or_policy: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    match scheme {
        Scheme::Waters | Scheme::WatersCca => {
            // CP-ABE: attrs_or_policy is a comma-separated list of attributes
            let mpk_cbor = fs::read(mpk_file)?;
            let msk_cbor = fs::read(msk_file)?;
            let mpk = cbor::decode_mpk(&mpk_cbor)?;
            let msk = cbor::decode_msk(&msk_cbor)?;

            let attrs: Vec<String> = attrs_or_policy.split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs)?;
            let sk_cbor = cbor::encode_sk(&sk)?;
            fs::write(sk_file, &sk_cbor)?;

            println!("Waters '11 secret key generated:");
            println!("  Attributes: {:?}", attrs);
        }
        Scheme::Gpsw => {
            // KP-ABE: attrs_or_policy is a policy string
            let mpk_cbor = fs::read(mpk_file)?;
            let msk_cbor = fs::read(msk_file)?;
            let mpk = cbor::decode_gpsw_mpk(&mpk_cbor)?;
            let msk = cbor::decode_gpsw_msk(&msk_cbor)?;

            let policy = parse_policy(attrs_or_policy)?;
            let sk = gpsw::keygen(&mut rng, &mpk, &msk, &policy)?;
            let sk_cbor = cbor::encode_gpsw_sk(&sk)?;
            fs::write(sk_file, &sk_cbor)?;

            println!("GPSW KP-ABE secret key generated:");
            println!("  Policy: {}", attrs_or_policy);
        }
        Scheme::Ac17 => {
            // CP-ABE: attrs_or_policy is a comma-separated list of attributes
            let mpk_json = fs::read(mpk_file)?;
            let msk_json = fs::read(msk_file)?;
            let mpk: ac17::Mpk = serde_json::from_slice(&mpk_json)?;
            let msk: ac17::Msk = serde_json::from_slice(&msk_json)?;

            let attrs: Vec<String> = attrs_or_policy.split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let sk = ac17::keygen(&mut rng, &mpk, &msk, &attrs)?;
            let sk_json = serde_json::to_vec(&sk)?;
            fs::write(sk_file, &sk_json)?;

            println!("AC17 CP-ABE secret key generated:");
            println!("  Attributes: {:?}", attrs);
        }
    }

    println!("  SK: {} ({} bytes)", sk_file.display(), fs::metadata(sk_file)?.len());
    Ok(())
}

fn do_encrypt(
    scheme: Scheme,
    mpk_file: &PathBuf,
    policy_or_attrs: &str,
    input: &PathBuf,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    let plaintext = fs::read(input)?;

    match scheme {
        Scheme::Waters => {
            let mpk_cbor = fs::read(mpk_file)?;
            let mpk = cbor::decode_mpk(&mpk_cbor)?;
            let policy = parse_policy(policy_or_attrs)?;
            let ct = waters::encrypt(&mut rng, &mpk, &policy, &plaintext)?;
            let ct_cbor = cbor::encode_full_ct(&ct)?;
            fs::write(output, &ct_cbor)?;
            println!("Waters '11 CPA encryption complete:");
        }
        Scheme::WatersCca => {
            let mpk_cbor = fs::read(mpk_file)?;
            let mpk = cbor::decode_mpk(&mpk_cbor)?;
            let policy = parse_policy(policy_or_attrs)?;
            let ct = waters_cca::encrypt(&mut rng, &mpk, &policy, &plaintext)?;
            let ct_cbor = cbor::encode_cca_full_ct(&ct)?;
            fs::write(output, &ct_cbor)?;
            println!("Waters '11 CCA encryption complete:");
        }
        Scheme::Gpsw => {
            // KP-ABE: policy_or_attrs is a comma-separated list of attributes
            let mpk_cbor = fs::read(mpk_file)?;
            let mpk = cbor::decode_gpsw_mpk(&mpk_cbor)?;
            let attrs: Vec<String> = policy_or_attrs.split(',')
                .map(|s| s.trim().to_string())
                .collect();
            let ct = gpsw::encrypt(&mut rng, &mpk, &attrs, &plaintext)?;
            let ct_cbor = cbor::encode_gpsw_full_ct(&ct)?;
            fs::write(output, &ct_cbor)?;
            println!("GPSW KP-ABE encryption complete:");
        }
        Scheme::Ac17 => {
            let mpk_json = fs::read(mpk_file)?;
            let mpk: ac17::Mpk = serde_json::from_slice(&mpk_json)?;
            let policy = parse_policy(policy_or_attrs)?;
            let ct = ac17::encrypt(&mut rng, &mpk, &policy, &plaintext)?;
            let ct_json = serde_json::to_vec(&ct)?;
            fs::write(output, &ct_json)?;
            println!("AC17 CP-ABE encryption complete:");
        }
    }

    println!("  Input: {} ({} bytes)", input.display(), plaintext.len());
    println!("  Output: {} ({} bytes)", output.display(), fs::metadata(output)?.len());
    Ok(())
}

fn do_decrypt(
    scheme: Scheme,
    mpk_file: &PathBuf,
    sk_file: &PathBuf,
    input: &PathBuf,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    match scheme {
        Scheme::Waters => {
            let mpk_cbor = fs::read(mpk_file)?;
            let sk_cbor = fs::read(sk_file)?;
            let ct_cbor = fs::read(input)?;

            let mpk = cbor::decode_mpk(&mpk_cbor)?;
            let sk = cbor::decode_sk(&sk_cbor)?;
            let ct = cbor::decode_full_ct(&ct_cbor)?;

            let plaintext = waters::decrypt(&mpk, &sk, &ct)?;
            fs::write(output, &plaintext)?;
            println!("Waters '11 CPA decryption complete:");
        }
        Scheme::WatersCca => {
            let mpk_cbor = fs::read(mpk_file)?;
            let sk_cbor = fs::read(sk_file)?;
            let ct_cbor = fs::read(input)?;

            let mpk = cbor::decode_mpk(&mpk_cbor)?;
            let sk = cbor::decode_sk(&sk_cbor)?;
            let ct = cbor::decode_cca_full_ct(&ct_cbor)?;

            let plaintext = waters_cca::decrypt(&mpk, &sk, &ct)?;
            fs::write(output, &plaintext)?;
            println!("Waters '11 CCA decryption complete:");
        }
        Scheme::Gpsw => {
            let mpk_cbor = fs::read(mpk_file)?;
            let sk_cbor = fs::read(sk_file)?;
            let ct_cbor = fs::read(input)?;

            let mpk = cbor::decode_gpsw_mpk(&mpk_cbor)?;
            let sk = cbor::decode_gpsw_sk(&sk_cbor)?;
            let ct = cbor::decode_gpsw_full_ct(&ct_cbor)?;

            let plaintext = gpsw::decrypt(&mpk, &sk, &ct)?;
            fs::write(output, &plaintext)?;
            println!("GPSW KP-ABE decryption complete:");
        }
        Scheme::Ac17 => {
            let mpk_json = fs::read(mpk_file)?;
            let sk_json = fs::read(sk_file)?;
            let ct_json = fs::read(input)?;

            let mpk: ac17::Mpk = serde_json::from_slice(&mpk_json)?;
            let sk: ac17::SecretKey = serde_json::from_slice(&sk_json)?;
            let ct: ac17::FullCiphertext = serde_json::from_slice(&ct_json)?;

            let plaintext = ac17::decrypt(&mpk, &sk, &ct)?;
            fs::write(output, &plaintext)?;
            println!("AC17 CP-ABE decryption complete:");
        }
    }

    println!("  Ciphertext: {} ({} bytes)", input.display(), fs::metadata(input)?.len());
    println!("  Plaintext: {} ({} bytes)", output.display(), fs::metadata(output)?.len());
    Ok(())
}

/// Parse a policy string into a PolicyNode
fn parse_policy(policy_str: &str) -> Result<PolicyNode, Box<dyn std::error::Error>> {
    waters::parse_policy(policy_str)
        .map_err(|e| format!("Failed to parse policy: {}", e).into())
}

// =============================================================================
// DABE (Decentralized Multi-Authority ABE) Functions
// =============================================================================

fn do_dabe_global_setup(gp_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    let gp = dabe::global_setup(&mut rng);

    let gp_json = serde_json::to_vec_pretty(&gp)?;
    fs::write(gp_file, &gp_json)?;

    println!("DABE global parameters generated:");
    println!("  GP: {} ({} bytes)", gp_file.display(), gp_json.len());
    Ok(())
}

fn do_dabe_auth_setup(
    gp_file: &PathBuf,
    authority_id: &str,
    apk_file: &PathBuf,
    ask_file: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let gp_json = fs::read(gp_file)?;
    let gp: dabe::GlobalParams = serde_json::from_slice(&gp_json)?;

    let (apk, ask) = dabe::authority_setup(&mut rng, &gp, authority_id);

    let apk_json = serde_json::to_vec_pretty(&apk)?;
    let ask_json = serde_json::to_vec_pretty(&ask)?;
    fs::write(apk_file, &apk_json)?;
    fs::write(ask_file, &ask_json)?;

    println!("DABE authority '{}' created:", authority_id);
    println!("  APK: {} ({} bytes)", apk_file.display(), apk_json.len());
    println!("  ASK: {} ({} bytes)", ask_file.display(), ask_json.len());
    Ok(())
}

fn do_dabe_auth_keygen(
    gp_file: &PathBuf,
    ask_file: &PathBuf,
    user_gid: &str,
    attrs: &str,
    ukc_file: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let gp_json = fs::read(gp_file)?;
    let gp: dabe::GlobalParams = serde_json::from_slice(&gp_json)?;

    let ask_json = fs::read(ask_file)?;
    let ask: dabe::AuthoritySk = serde_json::from_slice(&ask_json)?;

    let attr_list: Vec<String> = attrs.split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let ukc = dabe::authority_keygen(&mut rng, &gp, &ask, user_gid, &attr_list)?;

    let ukc_json = serde_json::to_vec_pretty(&ukc)?;
    fs::write(ukc_file, &ukc_json)?;

    println!("DABE key component issued by authority '{}':", ask.aid);
    println!("  User GID: {}", user_gid);
    println!("  Attributes: {:?}", attr_list);
    println!("  UKC: {} ({} bytes)", ukc_file.display(), ukc_json.len());
    Ok(())
}

fn do_dabe_aggregate(
    user_gid: &str,
    ukc_files: &str,
    usk_file: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let files: Vec<&str> = ukc_files.split(',').map(|s| s.trim()).collect();
    let mut components = Vec::new();

    for file in &files {
        let ukc_json = fs::read(file)?;
        let ukc: dabe::UserKeyComponent = serde_json::from_slice(&ukc_json)?;
        components.push(ukc);
    }

    let usk = dabe::aggregate_user_keys(user_gid, components)?;

    let usk_json = serde_json::to_vec_pretty(&usk)?;
    fs::write(usk_file, &usk_json)?;

    println!("DABE user secret key aggregated:");
    println!("  User GID: {}", user_gid);
    println!("  Authorities: {:?}", usk.components.keys().collect::<Vec<_>>());
    println!("  USK: {} ({} bytes)", usk_file.display(), usk_json.len());
    Ok(())
}

fn do_dabe_encrypt(
    gp_file: &PathBuf,
    apk_files: &str,
    policy: &str,
    input: &PathBuf,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let gp_json = fs::read(gp_file)?;
    let gp: dabe::GlobalParams = serde_json::from_slice(&gp_json)?;

    // Load all authority public keys
    let files: Vec<&str> = apk_files.split(',').map(|s| s.trim()).collect();
    let mut authority_pks: HashMap<String, dabe::AuthorityPk> = HashMap::new();
    for file in &files {
        let apk_json = fs::read(file)?;
        let apk: dabe::AuthorityPk = serde_json::from_slice(&apk_json)?;
        authority_pks.insert(apk.aid.clone(), apk);
    }

    let policy_node = parse_policy(policy)?;
    let plaintext = fs::read(input)?;

    let ct = dabe::encrypt(&mut rng, &gp, &authority_pks, &policy_node, &plaintext)?;

    let ct_json = serde_json::to_vec(&ct)?;
    fs::write(output, &ct_json)?;

    println!("DABE encryption complete:");
    println!("  Policy: {}", policy);
    println!("  Authorities: {:?}", authority_pks.keys().collect::<Vec<_>>());
    println!("  Input: {} ({} bytes)", input.display(), plaintext.len());
    println!("  Output: {} ({} bytes)", output.display(), ct_json.len());
    Ok(())
}

fn do_dabe_decrypt(
    gp_file: &PathBuf,
    usk_file: &PathBuf,
    input: &PathBuf,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let gp_json = fs::read(gp_file)?;
    let gp: dabe::GlobalParams = serde_json::from_slice(&gp_json)?;

    let usk_json = fs::read(usk_file)?;
    let usk: dabe::UserSecretKey = serde_json::from_slice(&usk_json)?;

    let ct_json = fs::read(input)?;
    let ct: dabe::FullCiphertext = serde_json::from_slice(&ct_json)?;

    let plaintext = dabe::decrypt(&gp, &usk, &ct)?;
    fs::write(output, &plaintext)?;

    println!("DABE decryption complete:");
    println!("  Ciphertext: {} ({} bytes)", input.display(), ct_json.len());
    println!("  Plaintext: {} ({} bytes)", output.display(), plaintext.len());
    Ok(())
}
