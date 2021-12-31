# vanitygen-bip39

<img width="747" alt="image" src="https://user-images.githubusercontent.com/893837/147824324-9d8891a9-87d2-44f6-aee5-a42a6e5e78c2.png">

> Generate Ethereum gas efficient addresses with leading zeros
>
> https://medium.com/coinmonks/on-efficient-ethereum-addresses-3fef0596e263

## Requirements

* Install rust (https://www.rust-lang.org/learn/get-started)

## Usage

* `git clone https://github.com/iam4x/vanitygen-bip39.git`
* `cargo build --release`
* `./target/release/vanitygen-bip39 --help`

## Options

* --threads (number of threads to use, default to max)
* --words (mnemonic words count 12 or 24, default to both)
* --score (min score results to display, default to 400 which is 4 leading zeros addresses)
* --webhooks (post webhook to call when matching criteria address is found)

## Todo

* [ ] release binaries for linux/windows/macOS
* [ ] release docker image
* [ ] improve documentation
