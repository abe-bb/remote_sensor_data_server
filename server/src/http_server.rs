mod users;

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Router,
};
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

pub async fn serve(tcp_listener: TcpListener) {
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register_sensor", post(register_sensor))
        .route("/deregister_sensor", post(deregister_sensor))
        .with_state(Arc::new(AppState {
            authorized_users: HashMap::new(),
        }));

    axum::serve(tcp_listener, app).await.unwrap();
}

async fn register_sensor(State(state): State<Arc<AppState>>, headers: HeaderMap) {}
async fn deregister_sensor(headers: HeaderMap) {}

struct AppState {
    authorized_users: HashMap<String, RsaPublicKey>,
}

#[derive(Serialize, Deserialize)]
struct RegisterSensor {
    user: String,
    sensor: String,
}

#[derive(Serialize, Deserialize)]
struct Sensor {
    sensor_name: String,
}

#[derive(Serialize, Deserialize)]
struct User {
    user: String,
    public_key: String,
}
