extern crate num_cpus;

use clap::Parser;
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

  if args.webhook != "" {
    println!("Webhook: {}", args.webhook);
  }

  println!("\n");

  let mut handles = vec![];

  for i in 0..args.threads {
    handles.push(thread::spawn(move || {
      find_vanity_address(i);
    }));
  }

  for handle in handles {
    handle.join().unwrap();
  }
}

fn find_vanity_address(thread: usize) {
  let args = Args::parse();
  let start = Instant::now();

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

  loop {
    let (mnemonic, address) = generate_address(words);
    let score = calc_score(&address);

    if score > args.score {
      // Print the result
      let duration = start.elapsed();
      println!("\n");
      println!("Time: {:?}", duration);
      println!("BIP39: {}", mnemonic);
      println!("Address: 0x{}", address);
      println!("Score: {}", score);
      println!("\n");

      // Send to webhook
      if args.webhook != "" {
        let mut map = HashMap::new();
        map.insert("duration", duration.as_secs().to_string());
        map.insert("mnemonic", mnemonic.phrase().to_string());
        map.insert("address", address.to_string());
        map.insert("score", score.to_string());

        let client = reqwest::blocking::Client::new();
        let _res = client.post(&args.webhook).json(&map).send();
      }
    }
  }
}

fn calc_score(address: &String) -> i32 {
  let mut score: i32 = 0;

  // calculate score of leading zeros into address (+10 per leading 0)
  for i in 0..address.len() {
    if address.chars().nth(i).unwrap() == '0' {
      score += 100;
    } else {
      break;
    }
  }

  // count occurence of 0 in string address
  for i in 0..address.len() {
    if address.chars().nth(i).unwrap() == '0' {
      score += 1;
    }
  }

  return score;
}

fn generate_address(words: Count) -> (Mnemonic, String) {
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
  let public_key = &public_key.serialize()[1..65];

  let addr = &keccak_hash(&public_key);
  let addr = &addr[(addr.len() - 40)..];

  return (mnemonic, addr.to_string());
}

fn keccak_hash(input: &[u8]) -> String {
  let mut hasher = Keccak::v256();
  let mut output = [0u8; 32];

  hasher.update(&input);
  hasher.finalize(&mut output);

  return hex::encode(output);
}
