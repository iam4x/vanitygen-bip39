extern crate num_cpus;

use clap::{Parser};
use regex::RegexBuilder;
use std::{collections::HashMap, time::Duration};
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

  #[clap(short, long, default_value = "")]
  regex: String,

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
  if args.regex.len() == 0 {
    println!("Minimum score shown: {}", args.score);
  } else {
    println!("Matching regex: {}", args.regex);
  }


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

  let re = RegexBuilder::new(args.regex.as_ref())
  .case_insensitive(true)
  .multi_line(false)
  .dot_matches_new_line(false)
  .ignore_whitespace(true)
  .unicode(true)
  .build().unwrap();

  loop {
    let (mnemonic, address) = generate_address(words);
    if args.regex.len() == 0 {
      let score = calc_score(&address);

      if score > args.score {
        let duration = start.elapsed();
        found_result(&args.webhook, duration, mnemonic, address, Some(score))
      }
    }else {
      if re.is_match(&address) {
        let duration = start.elapsed();
        found_result(&args.webhook, duration, mnemonic, address, None)
      }
    }

    if thread == 1 && args.benchmark {
      op_count += 1;

      if op_count == 10000 {
        let duration = op_start.elapsed().as_millis();
        let per_seconds = (1000 * op_count / duration) * args.threads as u128;

        println!("~{} OP/S", per_seconds);

        op_count = 0;
        op_start = Instant::now();
      }
    }
  }
}

fn found_result(webhook: &String, duration: Duration, mnemonic: Mnemonic, address: String, score: Option<i32>) {
  // Print the result
  println!("\n");
  println!("Time: {:?}", duration);
  println!("BIP39: {}", mnemonic);
  println!("Address: 0x{}", address);
  if let Some(score) = score {
    println!("Score: {}", score)
  }
  println!("\n");

  // Send to webhook
  if !webhook.is_empty() {
    let mut map = HashMap::new();
    map.insert("duration", duration.as_secs().to_string());
    map.insert("mnemonic", mnemonic.phrase().to_string());
    map.insert("address", address.to_string());
    if let Some(score) = score {
      map.insert("score", score.to_string());
    }    
    let client = reqwest::blocking::Client::new();
    let _res = client.post(webhook).json(&map).send();
  }
}

fn calc_score(address: &str) -> i32 {
  let mut score: i32 = 0;
  let mut has_reached_non_zero = false;

  // calculate score of leading zeros into address
  // +100 per leading 0
  // +1 per non-zero leading 0
  for c in address.chars() {
    if c != '0' {
      has_reached_non_zero = true;
    }

    if c == '0' && !has_reached_non_zero {
      score += 100;
    }

    if c == '0' && has_reached_non_zero {
      score += 1;
    }
  }

  score
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

  let addr = &keccak_hash(public_key);
  let addr = &addr[(addr.len() - 40)..];

  (mnemonic, addr.to_string())
}

fn keccak_hash(input: &[u8]) -> String {
  let mut hasher = Keccak::v256();
  let mut output = [0u8; 32];

  hasher.update(input);
  hasher.finalize(&mut output);

  hex::encode(output)
}
