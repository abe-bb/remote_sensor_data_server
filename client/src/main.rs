use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    net::TcpStream,
    thread::sleep,
    time::Duration,
};

use aes::Aes128;
use aes_gcm::Aes256Gcm;
use base64::{prelude::BASE64_STANDARD, Engine};
use ccm::{
    aead::Aead,
    consts::{U13, U4},
    AeadCore, Ccm, KeyInit,
};
use clap::Parser;
use reqwest::blocking::Client;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    sha2::Sha256,
    signature::{SignatureEncoding, SignerMut},
    Oaep, RsaPrivateKey, RsaPublicKey,
};

const SERVER_PREFIX: &str = "http://localhost:3000";

const EXAMPLE_SENSOR: &str = "{\"name\":\"example_sensor\",\"fields\":[\"x_accel\",\"y_accel\",\"z_accel\"],\"field_types\":[\"Integer\",\"Integer\",\"Integer\"],\"key\":[253,164,146,234,150,173,182,68,139,195,116,215,26,83,82,82],\"interval\":10,\"ccm_data\":{\"_direction_bit\":false,\"iv\":[0,1,2,3,4,5,6,7]}}";
const MISSING_SENSOR: &str = "{\"name\":\"missing_sensor\",\"fields\":[\"x_accel\",\"y_accel\",\"z_accel\"],\"field_types\":[\"Integer\",\"Integer\",\"Integer\"],\"key\":[253,164,146,234,150,173,182,68,139,195,116,215,26,83,82,82],\"interval\":10,\"ccm_data\":{\"_direction_bit\":false,\"iv\":[0,1,2,3,4,5,6,7]}}";
const BAD_SENSOR: &str = "{\"ae\":\"bad_sensor\",\"fields\":[\"x_accel\",\"y_accel\",\"z_accel\"],\"field_types\":[\"Integer\",\"Integer\",\"Integer\"],\"key\":[253,164,146,234,150,173,182,68,139,195,116,215,26,83,82,82],\"interval\":10,\"ccm_data\":{\"_direction_bit\":false,\"iv\":[0,1,2,3,4,5,6,7]}}";

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
        let server_pub_key = server_public_key.as_ref().unwrap();
        let url = SERVER_PREFIX.to_string() + "/register_sensor";
        sensor_action(url, EXAMPLE_SENSOR, server_pub_key);
    }

    // deregister test sensor
    if args.deregister_sensor {
        if server_public_key.is_none() {
            server_public_key = Some(get_server_public_key(&client));
        }
        let server_pub_key = server_public_key.as_ref().unwrap();
        let url = SERVER_PREFIX.to_string() + "/deregister_sensor";
        sensor_action(url, EXAMPLE_SENSOR, server_pub_key);
    }

    // register bad sensor
    if args.register_bad_sensor {
        if server_public_key.is_none() {
            server_public_key = Some(get_server_public_key(&client));
        }
        let server_pub_key = server_public_key.as_ref().unwrap();
        let url = SERVER_PREFIX.to_string() + "/register_sensor";
        sensor_action(url, BAD_SENSOR, server_pub_key);
    }

    // deregister bad sensor
    if args.deregister_bad_sensor {
        if server_public_key.is_none() {
            server_public_key = Some(get_server_public_key(&client));
        }
        let server_pub_key = server_public_key.as_ref().unwrap();
        let url = SERVER_PREFIX.to_string() + "/deregister_sensor";
        sensor_action(url, BAD_SENSOR, server_pub_key);
    }

    // deregister missing sensor
    if args.deregister_missing {
        if server_public_key.is_none() {
            server_public_key = Some(get_server_public_key(&client));
        }
        let server_pub_key = server_public_key.as_ref().unwrap();
        let url = SERVER_PREFIX.to_string() + "/deregister_sensor";
        sensor_action(url, MISSING_SENSOR, server_pub_key);
    }

    if args.test_data {
        test_data();
    }
}

struct CcmData {
    counter: u64,
    _direction: bool,
    iv: [u8; 8],
}

impl CcmData {
    fn new(iv: [u8; 8]) -> Self {
        CcmData {
            counter: 0,
            _direction: false,
            iv,
        }
    }

    fn increment_counter(&mut self) {
        self.counter += 1;
    }

    fn get_counter(&self) -> u64 {
        self.counter
    }

    fn generate_nonce(&self) -> [u8; 13] {
        let mut nonce: Vec<u8> = Vec::new();
        nonce.extend_from_slice(&self.counter.to_le_bytes()[..5]);
        nonce.extend_from_slice(&self.iv);

        assert_eq!(13, nonce.len());
        nonce.try_into().unwrap()
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

    /// deregister example_sensor
    #[arg(short, long)]
    deregister_sensor: bool,

    /// register badly formatted sensor
    #[arg(long)]
    register_bad_sensor: bool,

    /// deregister badly formatted sensor
    #[arg(long)]
    deregister_bad_sensor: bool,

    /// deregister missing_sensor
    #[arg(long)]
    deregister_missing: bool,

    #[arg(short, long)]
    test_data: bool,
}

pub type Aes128Ccm = Ccm<Aes128, U4, U13>;

fn test_data() {
    let file = File::open("../data.txt").unwrap();
    let reader = BufReader::new(file);

    let stream = TcpStream::connect("127.0.0.1:8000").unwrap();
    let mut writer = BufWriter::new(stream);

    let ccm_data = CcmData::new([0, 1, 2, 3, 4, 5, 6, 7]);

    let key = [
        253, 164, 146, 234, 150, 173, 182, 68, 139, 195, 116, 215, 26, 83, 82, 82,
    ];
    let cipher = Aes128Ccm::new_from_slice(&key).unwrap();

    let ciphertext = cipher
        .encrypt(
            (&ccm_data.generate_nonce()).into(),
            "{\"accel_x\": -608, \"accel_y\": -32, \"accel_z\": 800}".as_bytes(),
        )
        .unwrap();

    println!("ciphertext length: {}", ciphertext.len());

    for line in reader.lines() {
        let line = line.unwrap();
        writer.write(b">example_sensor<").unwrap();
        writer.write(&ccm_data.counter.to_le_bytes()[..5]).unwrap();

        let ciphertext = cipher
            .encrypt((&ccm_data.generate_nonce()).into(), line.as_bytes())
            .unwrap();

        let len: u8 = ciphertext.len() as u8;
        let len = [len];
        writer.write(&len).unwrap();
        writer.write(&ciphertext[..]).unwrap();
        writer.flush().unwrap();
        sleep(Duration::from_millis(900));
    }
}

fn sensor_action(url: String, body: &str, server_pub_key: &RsaPublicKey) {
    let (key_header, encrypted_body) = encrypt_body(body.as_bytes(), server_pub_key);

    let (_pub_key, priv_key) = load_user_keys();
    let mut signing_key: SigningKey<Sha256> = priv_key.into();
    let signature = sign_data(&encrypted_body, &mut signing_key);

    let client: Client = Client::new();
    let challenge = get_challenge(&client);
    let challenge_signature = sign_data(&challenge, &mut signing_key);

    let response = client
        .post(url)
        .header("user", "test_user")
        .header("signature", BASE64_STANDARD.encode(signature))
        .header("key", BASE64_STANDARD.encode(key_header))
        .header("challenge", BASE64_STANDARD.encode(challenge_signature))
        .body(encrypted_body)
        .send()
        .unwrap();

    println!(
        "Server Response: {:?}",
        response.status().canonical_reason()
    );
}

fn get_challenge(client: &Client) -> Vec<u8> {
    let response = client
        .get(SERVER_PREFIX.to_string() + "/challenge/test_user")
        .send()
        .unwrap();

    let challenge = response.bytes().unwrap().to_vec();
    challenge
}

fn sign_data(data: &[u8], signing_key: &mut SigningKey<Sha256>) -> Box<[u8]> {
    let signature = signing_key.sign(data);
    signature.to_bytes()
}

fn encrypt_body(body: &[u8], server_public_key: &RsaPublicKey) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let key = Aes256Gcm::generate_key(&mut rng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut rng);

    let padding = Oaep::new::<Sha256>();
    let mut key_nonce = Vec::new();
    key_nonce.extend(key.iter());
    key_nonce.extend(nonce.iter());

    let enc_key = server_public_key
        .encrypt(&mut rng, padding, &key_nonce)
        .unwrap();

    let enc_body = cipher.encrypt(&nonce, body).unwrap();

    (enc_key, enc_body)
}

fn load_user_keys() -> (RsaPublicKey, RsaPrivateKey) {
    let pub_key = fs::read_to_string("./user_key/user.pub").unwrap();
    let priv_key = fs::read_to_string("./user_key/user.priv").unwrap();

    let pub_key = RsaPublicKey::from_public_key_pem(&pub_key).unwrap();
    let priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_key).unwrap();

    (pub_key, priv_key)
}

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
