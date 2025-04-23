mod http_server;
mod tcp_server;

use ccm::aead::generic_array::GenericArray;
use rsa::{pkcs1v15::VerifyingKey, pkcs8::DecodePublicKey, sha2::Sha256, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, sync::Arc};

use tokio::{net::TcpListener, sync::RwLock};

const USER_PATH: &str = "authorized_users/";

#[tokio::main]
async fn main() {
    // set up tracing
    tracing_subscriber::fmt()
        .with_env_filter("info,project_server=debug")
        .init();

    let http_listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    let data_listener = TcpListener::bind("0.0.0.0:8000").await.unwrap();

    // let example_sensor = Sensor {
    //     name: "example_sensor".to_string(),
    //     fields: vec![
    //         "x_accel".to_string(),
    //         "y_accel".to_string(),
    //         "z_accel".to_string(),
    //     ],
    //     field_types: vec![FieldType::Integer, FieldType::Integer, FieldType::Integer],
    //     key: [
    //         0xfd, 0xa4, 0x92, 0xea, 0x96, 0xad, 0xb6, 0x44, 0x8b, 0xc3, 0x74, 0xd7, 0x1a, 0x53,
    //         0x52, 0x52,
    //     ],
    //     ccm_data: CcmData::new([0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]),
    //     interval: 10,
    // };

    let sensor_map = HashMap::new();
    // hashmap.insert("example_sensor".to_string(), example_sensor);
    let sensors = Arc::new(RwLock::new(sensor_map));

    let authorized_users = load_authorized_users();

    tokio::spawn(crate::tcp_server::serve(data_listener, sensors.clone()));
    crate::http_server::start(http_listener, authorized_users, sensors).await;
}

fn load_authorized_users() -> HashMap<String, VerifyingKey<Sha256>> {
    let mut users = HashMap::new();

    for dir_entry in fs::read_dir(USER_PATH).unwrap() {
        if dir_entry.is_err() {
            eprint!(
                "Encountered error reading users: {}",
                dir_entry.unwrap_err()
            );
            continue;
        }
        let dir_entry = dir_entry.unwrap();

        if !dir_entry.file_type().unwrap().is_file() {
            continue;
        }

        let user_filename = dir_entry.file_name().into_string().unwrap();
        let username = user_filename.split('.').next().unwrap();
        let key_string = fs::read_to_string(dir_entry.path()).unwrap();
        let pub_key = RsaPublicKey::from_public_key_pem(&key_string).unwrap();
        let key: VerifyingKey<Sha256> = pub_key.into();
        users.insert(username.to_owned(), key);
    }

    users
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Sensor {
    pub name: String,
    fields: Vec<String>,
    field_types: Vec<FieldType>,
    key: [u8; 16],
    interval: u32,
    ccm_data: CcmData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CcmData {
    _direction_bit: bool,
    iv: [u8; 8],
}

impl CcmData {
    pub fn new(iv: [u8; 8]) -> CcmData {
        CcmData {
            _direction_bit: false,
            iv,
        }
    }

    pub fn get_nonce(&self, counter: [u8; 5]) -> GenericArray<u8, ccm::consts::U13> {
        let mut le_bits: Vec<u8> = counter.into();
        le_bits.extend(self.iv);

        let nonce: [u8; 13] = le_bits.try_into().unwrap();

        nonce.into()
    }
}

impl Sensor {
    pub fn new(name: String, key: [u8; 16], iv: [u8; 8], interval: u32) -> Self {
        Sensor {
            name,
            fields: Vec::new(),
            field_types: Vec::new(),
            key,
            ccm_data: CcmData::new(iv),
            interval,
        }
    }

    pub fn add_field(&mut self, name: String, field_type: FieldType) {
        self.fields.push(name);
        self.field_types.push(field_type);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FieldType {
    Float,
    Integer,
}
