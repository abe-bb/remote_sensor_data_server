mod http_server;
mod tcp_server;

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

use tokio::{net::TcpListener, sync::RwLock};

#[tokio::main]
async fn main() {
    let http_listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    let data_listener = TcpListener::bind("0.0.0.0:8000").await.unwrap();

    let sensors = Arc::new(RwLock::new(HashMap::new()));

    tokio::spawn(crate::tcp_server::serve(data_listener, sensors.clone()));
    crate::http_server::start(http_listener, HashMap::new(), sensors).await;
}

#[derive(Serialize, Deserialize)]
pub struct Sensor {
    pub name: String,
    fields: Vec<String>,
    field_types: Vec<FieldType>,
}

impl Sensor {
    pub fn new(name: String) -> Self {
        Sensor {
            name,
            fields: Vec::new(),
            field_types: Vec::new(),
        }
    }

    pub fn add_field(&mut self, name: String, field_type: FieldType) {
        self.fields.push(name);
        self.field_types.push(field_type);
    }
}

#[derive(Serialize, Deserialize)]
pub enum FieldType {
    Float,
    Integer,
}
