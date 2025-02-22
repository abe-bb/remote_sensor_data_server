mod http_server;
mod tcp_server;

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
