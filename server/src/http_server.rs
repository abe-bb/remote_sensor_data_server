mod users;

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use rsa::{pkcs1::EncodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

const RSA_SIZE: usize = 2048;

pub async fn start(tcp_listener: TcpListener, authorized_users: HashMap<String, RsaPublicKey>) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, RSA_SIZE).expect("Couldn't generate rsa key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register_sensor", post(register_sensor))
        .route("/deregister_sensor", post(deregister_sensor))
        .route("/server_public_key", get(server_public_key))
        .with_state(Arc::new(AppState {
            authorized_users,
            server_public_key: pub_key,
            server_private_key: priv_key,
        }));

    axum::serve(tcp_listener, app).await.unwrap();
}

async fn register_sensor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // check for appropriate headers
    if !(headers.contains_key("user") && headers.contains_key("key")) {
        return StatusCode::BAD_REQUEST;
    }

    let (user_header, key_header) = (headers.get("user").unwrap(), headers.get("key").unwrap());

    // check for valid user and key format
    let Ok(user) = user_header.to_str() else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(key) = key_header.to_str() else {
        return StatusCode::BAD_REQUEST;
    };

    if !state.authorized_users.contains_key(user) {
        return StatusCode::UNAUTHORIZED;
    }

    StatusCode::OK
}
async fn deregister_sensor(headers: HeaderMap) {}

async fn server_public_key(State(state): State<Arc<AppState>>) -> String {
    state
        .server_public_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
}

struct AppState {
    authorized_users: HashMap<String, RsaPublicKey>,
    server_public_key: RsaPublicKey,
    server_private_key: RsaPrivateKey,
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
