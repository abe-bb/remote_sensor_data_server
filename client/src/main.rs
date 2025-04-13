use clap::Parser;
use reqwest::blocking::Client;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    RsaPublicKey,
};

const SERVER_PREFIX: &str = "http://localhost:3000";

fn main() {
    let args = Args::parse();

    let client = reqwest::blocking::Client::new();

    // retrieve and print server public key
    if args.server_key {
        let server_public_key = get_server_public_key(&client);
        println!(
            "Successfully retrieved server public key\n{}",
            server_public_key
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
        )
    }
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// get server public key
    #[arg(short, long)]
    server_key: bool,

    /// register example_sensor
    #[arg(short, long)]
    register_sensor: bool,
}

fn register_example_sensor(client: &Client) {}

fn get_server_public_key(client: &Client) -> RsaPublicKey {
    let server_string_key = client
        .get(SERVER_PREFIX.to_owned() + "/server_public_key")
        .send()
        .unwrap()
        .text()
        .unwrap();

    let server_public_key = RsaPublicKey::from_pkcs1_pem(&server_string_key).unwrap();

    server_public_key
}
