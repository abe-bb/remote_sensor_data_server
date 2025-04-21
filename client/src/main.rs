use std::fs;

use aes_gcm::Aes256Gcm;
use base64::{prelude::BASE64_STANDARD, Engine};
use ccm::{aead::Aead, AeadCore, KeyInit};
use clap::Parser;
use reqwest::blocking::Client;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    sha2::Sha256,
    Oaep, RsaPrivateKey, RsaPublicKey,
};

const SERVER_PREFIX: &str = "http://localhost:3000";

const EXAMPLE_SENSOR: &str = "{\"name\":\"example_sensor\",\"fields\":[\"x_accel\",\"y_accel\",\"z_accel\"],\"field_types\":[\"Integer\",\"Integer\",\"Integer\"],\"key\":[253,164,146,234,150,173,182,68,139,195,116,215,26,83,82,82],\"interval\":10,\"ccm_data\":{\"_direction_bit\":false,\"iv\":[0,1,2,3,4,5,6,7]}}";
const BAD_SENSOR: &str = "{\"name\":\"bad_sensor\",\"fields\":[\"x_accel\",\"y_accel\",\"z_accel\"],\"field_types\":[\"Integer\",\"Integer\",\"Integer\"],\"key\":[253,164,146,234,150,173,182,68,139,195,116,215,26,83,82,82],\"interval\":10,\"ccm_data\":{\"_direction_bit\":false,\"iv\":[0,1,2,3,4,5,6,7]}}";

fn main() {
    let args = Args::parse();

    let client = reqwest::blocking::Client::new();

    let mut server_public_key: Option<RsaPublicKey> = None;
    // retrieve and print server public key
    if args.server_key {
        server_public_key = Some(get_server_public_key(&client));
        println!(
            "Successfully retrieved server public key\n{}",
            server_public_key
                .as_ref()
                .unwrap()
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
        )
    }
    // register test sensor
    if args.register_sensor {
        if server_public_key.is_none() {
            server_public_key = Some(get_server_public_key(&client));
        }

        let (key_header, encrypted_body) = encrypt_body(
            EXAMPLE_SENSOR.as_bytes(),
            server_public_key.as_ref().unwrap(),
        );
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

fn encrypt_body(body: &[u8], server_public_key: &RsaPublicKey) -> (String, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let key = Aes256Gcm::generate_key(&mut rng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut rng);

    let padding = Oaep::new::<Sha256>();
    let mut key_nonce = Vec::new();
    key_nonce.extend(key.iter());
    key_nonce.extend(nonce.iter());

    let enc_data = server_public_key
        .encrypt(&mut rng, padding, &key_nonce)
        .unwrap();

    let enc_body = cipher.encrypt(&nonce, EXAMPLE_SENSOR.as_bytes()).unwrap();
    let key_header = BASE64_STANDARD.encode(enc_data);

    (key_header, enc_body)
}

fn load_user_keys() -> (RsaPublicKey, RsaPrivateKey) {
    let pub_key = fs::read_to_string("./user_key/user.pub").unwrap();
    let priv_key = fs::read_to_string("./user_key/user.priv").unwrap();

    let pub_key = RsaPublicKey::from_public_key_pem(&pub_key).unwrap();
    let priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_key).unwrap();

    (pub_key, priv_key)
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
