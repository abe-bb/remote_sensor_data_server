mod http_server;
mod tcp_server;

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

use tokio::{net::TcpListener, sync::RwLock};

#[tokio::main]
async fn main() {
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
}

impl Sensor {
    pub fn new(name: String, key: [u8; 16]) -> Self {
        Sensor {
            name,
            fields: Vec::new(),
            field_types: Vec::new(),
            key,
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
