extern crate num_cpus;
extern crate secp256k1;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use hex;
use std::str::FromStr;
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::ChildNumber;

use bip39::{Language, Mnemonic, MnemonicType, Seed};

use secp256k1::key::{PublicKey, SecretKey};
use serde::Serialize;
use sha3::{Digest, Keccak256};

const BENCHMARK: bool = false;
const MIN_SCORE: i32 = 300;

fn main() {
  let threads: usize = num_cpus::get();

  println!("Starting vanitygen-bip39-rust on {} threads", threads);

  let last_score = Arc::new(Mutex::new(0));
  let count = Arc::new(Mutex::new(0));

  let mut handles = vec![];

  for _i in 0..threads {
    let last_score = Arc::clone(&last_score);
    let count = Arc::clone(&count);

    handles.push(thread::spawn(move || {
      let start = Instant::now();
      main_loop(start, last_score, count);
    }))
  }

  if BENCHMARK == true {
    let start = Instant::now();
    benchmark_count(start, count);
  }

  for handle in handles {
    handle.join().unwrap();
  }
}

fn benchmark_count(start: Instant, count: Arc<Mutex<i32>>) {
  let elapsed = start.elapsed();
  let count_per_sec = *count.lock().unwrap() as f64 / elapsed.as_secs_f64();

  if count_per_sec > 0.0 {
    println!("{} addresses generated per second", count_per_sec);
  }

  thread::sleep(std::time::Duration::from_secs(10));
  benchmark_count(start, count);
}

fn main_loop(start: Instant, last_score: Arc<Mutex<i32>>, count: Arc<Mutex<i32>>) {
  loop {
    let (mnemonic, address) = generate_address();
    let score = calc_score(&address);

    if BENCHMARK == true {
      *count.lock().unwrap() += 1;
    }

    if *last_score.lock().unwrap() < score && score > MIN_SCORE {
      println!("\n");

      let duration = start.elapsed();
      println!("Time: {:?}", duration);

      println!("BIP39: {}", mnemonic);
      println!("Address: 0x{}", address);
      println!("Score: {}", score);

      *last_score.lock().unwrap() = score;
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

fn generate_address() -> (Mnemonic, String) {
  let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);

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
