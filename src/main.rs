extern crate num_cpus;

use clap::Parser;
use hex::encode;
use std::collections::HashMap;
use std::str::FromStr;
use std::thread;
use std::time::Instant;

use bip0039::{Count, Mnemonic};
use libsecp256k1::{PublicKey, SecretKey};
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;
use tiny_keccak::{Hasher, Keccak};

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    #[clap(short, long, default_value_t = 400)]
    score: i32,

    #[clap(short, long, default_value_t = 0)]
    words: i32,

    #[clap(short, long, default_value_t = num_cpus::get())]
    threads: usize,

    #[clap(short = 'W', long, default_value = "")]
    webhook: String,

    #[clap(short, long)]
    benchmark: bool,
}

fn main() {
    let args = Args::parse();

    println!("\n");
    println!("                       .__  __                                       ___.   .__      ________  ________              ");
    println!("  ___  _______    ____ |__|/  |_ ___.__. ____   ____   ____          \\_ |__ |__|_____\\_____  \\/   __   \\         ");
    println!("  \\  \\/ /\\__  \\  /    \\|  \\   __<   |  |/ ___\\_/ __ \\ /    \\   ______ | __ \\|  \\____ \\ _(__  <\\____    /");
    println!("   \\   /  / __ \\|   |  \\  ||  |  \\___  / /_/  >  ___/|   |  \\ /_____/ | \\_\\ \\  |  |_> >       \\  /    /     ");
    println!("    \\_/  (____  /___|  /__||__|  / ____\\___  / \\___  >___|  /         |___  /__|   __/______  / /____/            ");
    println!("              \\/     \\/          \\/   /_____/      \\/     \\/              \\/   |__|         \\/                ");
    println!("\n");

    println!("Threads count: {}", args.threads);
    println!("Minimum score shown: {}", args.score);

    if args.words > 0 {
        println!("Mnemonic words count: {}", args.words);
    }

    if !args.webhook.is_empty() {
        println!("Webhook: {}", args.webhook);
    }

    if args.benchmark {
        println!("Benchmark: true");
    }

    println!("\n");

    let mut handles = vec![];

    for i in 0..args.threads {
        handles.push(thread::spawn(move || {
            find_vanity_address(i, args.threads, args.benchmark);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

fn find_vanity_address(thread: usize, threads_count: usize, bench: bool) {
    let args = Args::parse();
    let start = Instant::now();

    let mut op_count: u128 = 0;
    let mut op_start = Instant::now();

    // default words to 12 and 24 depends on thread
    // allow to search in different bip39 ranges for each thread
    let mut words = if thread % 2 == 1 {
        Count::Words12
    } else {
        Count::Words24
    };

    // respect user input if specified words count in args
    if args.words == 12 {
        words = Count::Words12;
    } else if args.words == 24 {
        words = Count::Words24;
    }

    let mut output = [0u8; 32];

    loop {
        let (mnemonic, public) = generate_address(words);
        let public = &public.serialize()[1..65];

        keccak_hash_in_place(public, &mut output);
        let score = calc_score(&output);

        if score > args.score {
            // Print the result
            let address = &encode(&output[(output.len() - 20)..]);
            let duration = start.elapsed();
            println!("\n");
            println!("Time: {:?}", duration);
            println!("BIP39: {}", mnemonic);
            println!("Address: 0x{}", address);
            println!("Score: {}", score);
            println!("\n");

            // Send to webhook
            if !args.webhook.is_empty() {
                let mut map = HashMap::new();
                map.insert("duration", duration.as_secs().to_string());
                map.insert("mnemonic", mnemonic.phrase().to_string());
                map.insert("address", address.to_string());
                map.insert("score", score.to_string());

                let client = reqwest::blocking::Client::new();
                let _res = client.post(&args.webhook).json(&map).send();
            }
        }

        if thread == 1 && bench {
            op_count += 1;

            if op_count == 10000 {
                let duration = op_start.elapsed().as_millis();
                let per_seconds = (1000 * op_count / duration) * threads_count as u128;

                println!("~{} OP/S", per_seconds);

                op_count = 0;
                op_start = Instant::now();
            }
        }
    }
}

const NIBBLE_MASK: u8 = 0x0F;
const SCORE_FOR_LEADING_ZERO: i32 = 100;
const SCORE_FOR_OTHER_ZEROS: i32 = 1;

fn calc_score(address: &[u8]) -> i32 {
    let mut score: i32 = 0;
    let mut has_reached_non_zero = false;

    for &byte in &address[(address.len() - 20)..] {
        // Check first half-byte (or nibble)
        let first_half = byte >> 4;

        if first_half != 0 {
            has_reached_non_zero = true;
        }

        if first_half == 0 && !has_reached_non_zero {
            score += SCORE_FOR_LEADING_ZERO;
        } else if first_half == 0 && has_reached_non_zero {
            score += SCORE_FOR_OTHER_ZEROS;
        }

        // Check second half-byte (or nibble)
        let second_half = byte & NIBBLE_MASK;

        if second_half != 0 {
            has_reached_non_zero = true;
        }

        if second_half == 0 && !has_reached_non_zero {
            score += SCORE_FOR_LEADING_ZERO;
        } else if second_half == 0 && has_reached_non_zero {
            score += SCORE_FOR_OTHER_ZEROS;
        }
    }

    score
}

fn generate_address(words: Count) -> (Mnemonic, PublicKey) {
    let mnemonic = Mnemonic::generate(words);
    let seed = mnemonic.to_seed("");

    let hdwallet = ExtendedPrivKey::derive(&seed, "m/44'/60'/0'/0").unwrap();
    let account0 = hdwallet.child(ChildNumber::from_str("0").unwrap()).unwrap();

    let secret_key = SecretKey::parse(&account0.secret());
    let secret_key = match secret_key {
        Ok(sk) => sk,
        Err(_) => panic!("Failed to parse secret key"),
    };

    let public_key = PublicKey::from_secret_key(&secret_key);

    (mnemonic, public_key)
}

fn keccak_hash_in_place(input: &[u8], output: &mut [u8; 32]) {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}
