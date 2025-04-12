use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};

const SERVER_PREFIX: &str = "https://localhost:3000";

fn main() {
    let client = reqwest::blocking::Client::new();
    let server_string_key = client
        .get(SERVER_PREFIX.to_owned() + "/server_public_key")
        .send()
        .unwrap()
        .text()
        .unwrap();

    let server_public_key = RsaPublicKey::from_pkcs1_pem(&server_string_key);
}
