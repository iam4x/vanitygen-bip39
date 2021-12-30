extern crate num_cpus;
extern crate secp256k1;

use clap::Parser;
use std::str::FromStr;
use std::thread;
use std::time::Instant;

use hex;

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use secp256k1::key::{PublicKey, SecretKey};
use serde::Serialize;
use sha3::{Digest, Keccak256};
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
  #[clap(short, long, default_value_t = 400)]
  score: i32,

  #[clap(short, long, default_value_t = 12)]
  words: i32,

  #[clap(short, long, default_value_t = num_cpus::get())]
  threads: usize,
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
  println!("Mnemonic words count: {}", args.words);
  println!("Minimum score shown: {}", args.score);
  println!("\n");

  let mut handles = vec![];

  for _i in 0..args.threads {
    handles.push(thread::spawn(move || {
      find_vanity_address();
    }));
  }

  for handle in handles {
    handle.join().unwrap();
  }
}

fn find_vanity_address(
) {
  let args = Args::parse();
  let start = Instant::now();

  loop {
    let (mnemonic, address) = generate_address(args.words);
    let score = calc_score(&address);

    if score > args.score {
      let duration = start.elapsed();

      println!("\n");
      println!("Time: {:?}", duration);
      println!("BIP39: {}", mnemonic);
      println!("Address: 0x{}", address);
      println!("Score: {}", score);
      println!("\n");
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

fn generate_address(words: i32) -> (Mnemonic, String) {
  let mut w = MnemonicType::Words12;

  if words == 24 {
    w = MnemonicType::Words24;
  }

  let mnemonic = Mnemonic::new(w, Language::English);

  let seed = Seed::new(&mnemonic, ""); // 128 hex chars = 512 bits
  let seed_bytes: &[u8] = seed.as_bytes();

  let base_ext = ExtendedPrivKey::derive(seed_bytes, "m/44'/60'/0'/0").unwrap();
  let child_ext = base_ext.child(ChildNumber::from_str("0").unwrap()).unwrap();

  let context = secp256k1::Secp256k1::new();
  let secret_key = SecretKey::from_slice(&child_ext.secret());
  let public_key = PublicKey::from_secret_key(&context, &secret_key.unwrap());

  // remove 04 from the beginning of the public key
  let pk = &public_key.serialize_uncompressed()[1..65];

  let addr = &keccak_hash(&pk);
  let addr = &addr[(addr.len() - 40)..];

  return (mnemonic, addr.to_string());
}

fn keccak_hash<T>(data: &T) -> String
where
  T: ?Sized + Serialize + AsRef<[u8]>,
{
  let mut hasher = Keccak256::new();
  hasher.update(data);

  let result = hasher.finalize();
  let hex_r = hex::encode(result);

  return hex_r;
}
