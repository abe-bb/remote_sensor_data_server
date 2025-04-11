mod http_server;
mod tcp_server;

use ccm::aead::generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

use tokio::{net::TcpListener, sync::RwLock};

#[tokio::main]
async fn main() {
    // set up tracing
    tracing_subscriber::fmt()
        .with_env_filter("info,project_server=debug,tower_http=trace,axum=trace")
        .init();

    let http_listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    let data_listener = TcpListener::bind("0.0.0.0:8000").await.unwrap();

    let example_sensor = Sensor {
        name: "example_sensor".to_string(),
        fields: vec![
            "x_accel".to_string(),
            "y_accel".to_string(),
            "z_accel".to_string(),
        ],
        field_types: vec![FieldType::Integer, FieldType::Integer, FieldType::Integer],
        key: [
            0xfd, 0xa4, 0x92, 0xea, 0x96, 0xad, 0xb6, 0x44, 0x8b, 0xc3, 0x74, 0xd7, 0x1a, 0x53,
            0x52, 0x52,
        ],
        ccm_data: CcmData::new([0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]),
    };

    let mut hashmap = HashMap::new();
    hashmap.insert("example_sensor".to_string(), example_sensor);

    let sensors = Arc::new(RwLock::new(hashmap));

    tokio::spawn(crate::tcp_server::serve(data_listener, sensors.clone()));
    crate::http_server::start(http_listener, HashMap::new(), sensors).await;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Sensor {
    pub name: String,
    fields: Vec<String>,
    field_types: Vec<FieldType>,
    key: [u8; 16],
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
    pub fn new(name: String, key: [u8; 16], iv: [u8; 8]) -> Self {
        Sensor {
            name,
            fields: Vec::new(),
            field_types: Vec::new(),
            key,
            ccm_data: CcmData::new(iv),
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
