use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};

use base64::{prelude::BASE64_STANDARD, Engine};
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    sha2::Sha256,
    signature::Verifier,
    RsaPrivateKey, RsaPublicKey,
};
use tokio::{net::TcpListener, sync::RwLock};

use crate::Sensor;

const _RSA_SIZE: usize = 2048;

fn create_router(
    authorized_users: HashMap<String, VerifyingKey<Sha256>>,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
) -> Router {
    // let mut rng = rand::thread_rng();
    // let priv_key = RsaPrivateKey::new(&mut rng, RSA_SIZE).expect("Couldn't generate rsa key");
    // let pub_key = RsaPublicKey::from(&priv_key);
    let (priv_key, pub_key) = create_server_data();

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!\n" }))
        .route("/register_sensor", post(register_sensor))
        .route("/deregister_sensor", post(deregister_sensor))
        .route("/server_public_key", get(server_public_key))
        .with_state(Arc::new(AppState {
            authorized_users,
            server_public_key: pub_key,
            _server_private_key: priv_key,
            sensors,
        }));

    app
}

pub async fn start(
    tcp_listener: TcpListener,
    mut authorized_users: HashMap<String, VerifyingKey<Sha256>>,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
) {
    let (_priv_key, pub_key) = create_server_data();
    authorized_users.insert("example_user".to_owned(), pub_key.into());
    let app = create_router(authorized_users, sensors);

    axum::serve(tcp_listener, app).await.unwrap();
}

async fn register_sensor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (status, sensor) =
        authenticate_and_parse_sensor(headers, body, &state.authorized_users).await;

    let Some(sensor) = sensor else {
        return status;
    };

    // scope for write access to hashmap
    {
        let mut write_lock = state.sensors.write().await;
        // check if sensor name is already taken
        if write_lock.contains_key(&sensor.name) {
            return StatusCode::CONFLICT;
        }

        // add new sensor
        write_lock.insert(sensor.name.clone(), sensor);
    }; // write lock dropped

    StatusCode::OK
}
async fn deregister_sensor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (status, sensor) =
        authenticate_and_parse_sensor(headers, body, &state.authorized_users).await;

    let Some(sensor) = sensor else {
        return status;
    };

    // scope for write access to hashmap
    {
        let mut write_lock = state.sensors.write().await;
        if let Some(_) = write_lock.remove(&sensor.name) {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        }
    } // write lock dropped
}

async fn server_public_key(State(state): State<Arc<AppState>>) -> String {
    state
        .server_public_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
}

async fn authenticate_and_parse_sensor(
    headers: HeaderMap,
    body: Bytes,
    authorized_users: &HashMap<String, VerifyingKey<Sha256>>,
) -> (StatusCode, Option<Sensor>) {
    // check for appropriate headers
    if !(headers.contains_key("user") && headers.contains_key("signature")) {
        return (StatusCode::BAD_REQUEST, None);
    }

    let (user_header, signature_header) = (
        headers.get("user").unwrap(),
        headers.get("signature").unwrap(),
    );

    // check for valid user, signature, and key
    let Ok(user) = user_header.to_str() else {
        println!("missing user");
        return (StatusCode::BAD_REQUEST, None);
    };
    let Ok(signature) = signature_header.to_str() else {
        println!("missing signature");
        return (StatusCode::BAD_REQUEST, None);
    };

    // convert from Base64 to binary
    let Ok(signature) = BASE64_STANDARD.decode(signature) else {
        println!("missing signature");
        return (StatusCode::BAD_REQUEST, None);
    };

    // construct signature from binary
    let Ok(signature) = Signature::try_from(&signature[..]) else {
        println!("invalid signature");
        return (StatusCode::BAD_REQUEST, None);
    };

    // check that the user exists
    if !authorized_users.contains_key(user) {
        println!("user: {} is not authorized", user);
        return (StatusCode::UNAUTHORIZED, None);
    }

    // check that signature matches declared user
    let user_verification_key = authorized_users.get(user).unwrap();
    let Ok(_) = user_verification_key.verify(&body[..], &signature) else {
        println!("signature verification failed");
        return (StatusCode::UNAUTHORIZED, None);
    };

    // Deserialize sensor from body
    let Ok(sensor): Result<Sensor, _> = serde_json::from_slice(&body) else {
        return (StatusCode::BAD_REQUEST, None);
    };

    (StatusCode::OK, Some(sensor))
}

fn create_server_data() -> (RsaPrivateKey, RsaPublicKey) {
    let user_pub_key: RsaPublicKey = RsaPublicKey::from_public_key_pem(
        "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9SjDjbu3d5NG9DfHgiJL
oV+ITz0TeGIzl1Xt+Sqt1ZhtyjPTRpaxyIRg/xYJqkz6/W7b1pxY9Bv9geBxts28
coYp3a0CBXrCF0CvJP2LmOwZIACbaLzsY6xzJT4udFONBNMd/nd9Cc+didhJLttz
x+ARknK7ekHTl0vwdkH5IeFYJ+3gW7TPZTAFmc7YHCmrEfXPQULagxECo9Jhfogl
vnTTnYSdLeqL3kizKq1bdM8H5MbfKJvEeU4rNj2r6Zj4nijzti2+XgzmTuk2kfWq
neQ92PvdPLq7T1VAWnoNrsE3e8i3v8XnTtaNfI3ErUvZ8023JQyZd52E43oHg/1Y
WwIDAQAB
-----END PUBLIC KEY-----",
    )
    .unwrap();

    let user_priv_key: RsaPrivateKey = RsaPrivateKey::from_pkcs8_pem(
        "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD1KMONu7d3k0b0
N8eCIkuhX4hPPRN4YjOXVe35Kq3VmG3KM9NGlrHIhGD/FgmqTPr9btvWnFj0G/2B
4HG2zbxyhindrQIFesIXQK8k/YuY7BkgAJtovOxjrHMlPi50U40E0x3+d30Jz52J
2Eku23PH4BGScrt6QdOXS/B2Qfkh4Vgn7eBbtM9lMAWZztgcKasR9c9BQtqDEQKj
0mF+iCW+dNOdhJ0t6oveSLMqrVt0zwfkxt8om8R5Tis2PavpmPieKPO2Lb5eDOZO
6TaR9aqd5D3Y+908urtPVUBaeg2uwTd7yLe/xedO1o18jcStS9nzTbclDJl3nYTj
egeD/VhbAgMBAAECggEBAKV97wQuQ5skgDE7tiHSpNs6cfmLcSlCoTD3gL1CYjZd
vz9P3L852qlRM2j+p2eer4+E1kH5KNMgUfDqYdjU6PEmP/y0XTj1tS+dKp39yc5h
ElTYFBCP98MRFml9oD5GaFtpaEXuwylsTRxQNJa87Vtvlm0VphjRdtQbHye1QUfs
VBvREe1rbMB1U8rKUZ7vdw6XvCnsRDRx1qQUGjMgYUDW5ZGV4SksIpuXdT6hrUiq
HB0F8di3dgS4KOd9yshJJvrIgSMvRs6lNbeJ9DSYvT/2zCCcYdxEvdSLlcRT6RTQ
D5xmTGyCI3OtKpRJRuakgHC8NZ7edngX7nQwGTFb9IECgYEA/2HxwsMkf++hFjtI
FDT2VeEC+40hBX7ug2ZNC/RwCawIGQj6z3/Ypk0eb++xsHBx3WHzm2+cOu+NLs0w
bwNmC+eRAYMZTvQI1UZ8e/UAzbWl/BeTffbBYWbWl0/FQVyu8874L1QSSjRnznnS
kh9MDYx4r6kOg/4W3P+4OFvyeVcCgYEA9cB+BtQcnJtp9/qjHgc6nMV2m2bd4oeS
XoX0E6tFc47/iHEyYu8UsuC7D+cPaZdwrI2NpYBIIcV7d7yeNtiQ51IMWaSWdeg7
xysNwq0tPK7ouuhWTbl7p1lNcAJo/DrHhZ3fwi2VtWtxEiT3OJK/aQbXB4NIffdc
B0aN+ewzwp0CgYAbu7oyaVi0YASBUozATQQXTWkygh/85cznDhv92Vy1YC488cGy
+PJBFQziIQiN3Zgv72wyDAvORqdxVq0U0SyqzEnt/RupfEzdRFtOZsvgiwJsfu7w
dfSILE/PfMUyFOuW5HoFQb7+ufQv8wDQB4AN1JxijxxZbyVyeH67+Bg73wKBgQCn
7pIwOGIU4l7Xhf5RVr9Gwej66KBXXC05SnAvwKoE/YLAyhmUYavTUJ6Dj3GIxmPI
hjJ1FeQ0r65fdBTphbP/XqHx3/axO7EduN3+Wji/bwa6MmpHUqidAvlXwU3cjo4p
UGjHWD8lafYqX/hQQHdsXbAzAhNXgODyV9RNJIt6QQKBgQCDIfLzVuZ88p/VQQ2v
YwOTO9kGfr2Z+EvdB6K/Z20fQdvT2b07M5G16OSIkTAzjuN4k08/eK/gOq2mJMK1
BDELtfUlKJKksDmcx3zNXH1oXUEwygWHtgNnbvhv7lrZrfEXFORU8WV4c/2OAlM1
pUt9ee4TLb/KxjITKaebsuHFZg==
-----END PRIVATE KEY-----",
    )
    .unwrap();

    (user_priv_key.into(), user_pub_key.into())
}

struct AppState {
    authorized_users: HashMap<String, VerifyingKey<Sha256>>,
    server_public_key: RsaPublicKey,
    _server_private_key: RsaPrivateKey,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use axum::{body::Body, http::Request};
    use rsa::{
        pkcs1v15::SigningKey,
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        signature::{SignatureEncoding, SignerMut},
    };
    use tower::ServiceExt;

    fn create_user_data() -> (SigningKey<Sha256>, VerifyingKey<Sha256>) {
        let user_pub_key: RsaPublicKey = RsaPublicKey::from_public_key_pem(
            "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9SjDjbu3d5NG9DfHgiJL
oV+ITz0TeGIzl1Xt+Sqt1ZhtyjPTRpaxyIRg/xYJqkz6/W7b1pxY9Bv9geBxts28
coYp3a0CBXrCF0CvJP2LmOwZIACbaLzsY6xzJT4udFONBNMd/nd9Cc+didhJLttz
x+ARknK7ekHTl0vwdkH5IeFYJ+3gW7TPZTAFmc7YHCmrEfXPQULagxECo9Jhfogl
vnTTnYSdLeqL3kizKq1bdM8H5MbfKJvEeU4rNj2r6Zj4nijzti2+XgzmTuk2kfWq
neQ92PvdPLq7T1VAWnoNrsE3e8i3v8XnTtaNfI3ErUvZ8023JQyZd52E43oHg/1Y
WwIDAQAB
-----END PUBLIC KEY-----",
        )
        .unwrap();

        let user_priv_key: RsaPrivateKey = RsaPrivateKey::from_pkcs8_pem(
            "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD1KMONu7d3k0b0
N8eCIkuhX4hPPRN4YjOXVe35Kq3VmG3KM9NGlrHIhGD/FgmqTPr9btvWnFj0G/2B
4HG2zbxyhindrQIFesIXQK8k/YuY7BkgAJtovOxjrHMlPi50U40E0x3+d30Jz52J
2Eku23PH4BGScrt6QdOXS/B2Qfkh4Vgn7eBbtM9lMAWZztgcKasR9c9BQtqDEQKj
0mF+iCW+dNOdhJ0t6oveSLMqrVt0zwfkxt8om8R5Tis2PavpmPieKPO2Lb5eDOZO
6TaR9aqd5D3Y+908urtPVUBaeg2uwTd7yLe/xedO1o18jcStS9nzTbclDJl3nYTj
egeD/VhbAgMBAAECggEBAKV97wQuQ5skgDE7tiHSpNs6cfmLcSlCoTD3gL1CYjZd
vz9P3L852qlRM2j+p2eer4+E1kH5KNMgUfDqYdjU6PEmP/y0XTj1tS+dKp39yc5h
ElTYFBCP98MRFml9oD5GaFtpaEXuwylsTRxQNJa87Vtvlm0VphjRdtQbHye1QUfs
VBvREe1rbMB1U8rKUZ7vdw6XvCnsRDRx1qQUGjMgYUDW5ZGV4SksIpuXdT6hrUiq
HB0F8di3dgS4KOd9yshJJvrIgSMvRs6lNbeJ9DSYvT/2zCCcYdxEvdSLlcRT6RTQ
D5xmTGyCI3OtKpRJRuakgHC8NZ7edngX7nQwGTFb9IECgYEA/2HxwsMkf++hFjtI
FDT2VeEC+40hBX7ug2ZNC/RwCawIGQj6z3/Ypk0eb++xsHBx3WHzm2+cOu+NLs0w
bwNmC+eRAYMZTvQI1UZ8e/UAzbWl/BeTffbBYWbWl0/FQVyu8874L1QSSjRnznnS
kh9MDYx4r6kOg/4W3P+4OFvyeVcCgYEA9cB+BtQcnJtp9/qjHgc6nMV2m2bd4oeS
XoX0E6tFc47/iHEyYu8UsuC7D+cPaZdwrI2NpYBIIcV7d7yeNtiQ51IMWaSWdeg7
xysNwq0tPK7ouuhWTbl7p1lNcAJo/DrHhZ3fwi2VtWtxEiT3OJK/aQbXB4NIffdc
B0aN+ewzwp0CgYAbu7oyaVi0YASBUozATQQXTWkygh/85cznDhv92Vy1YC488cGy
+PJBFQziIQiN3Zgv72wyDAvORqdxVq0U0SyqzEnt/RupfEzdRFtOZsvgiwJsfu7w
dfSILE/PfMUyFOuW5HoFQb7+ufQv8wDQB4AN1JxijxxZbyVyeH67+Bg73wKBgQCn
7pIwOGIU4l7Xhf5RVr9Gwej66KBXXC05SnAvwKoE/YLAyhmUYavTUJ6Dj3GIxmPI
hjJ1FeQ0r65fdBTphbP/XqHx3/axO7EduN3+Wji/bwa6MmpHUqidAvlXwU3cjo4p
UGjHWD8lafYqX/hQQHdsXbAzAhNXgODyV9RNJIt6QQKBgQCDIfLzVuZ88p/VQQ2v
YwOTO9kGfr2Z+EvdB6K/Z20fQdvT2b07M5G16OSIkTAzjuN4k08/eK/gOq2mJMK1
BDELtfUlKJKksDmcx3zNXH1oXUEwygWHtgNnbvhv7lrZrfEXFORU8WV4c/2OAlM1
pUt9ee4TLb/KxjITKaebsuHFZg==
-----END PRIVATE KEY-----",
        )
        .unwrap();

        (user_priv_key.into(), user_pub_key.into())
    }

    #[tokio::test]
    async fn register_missing_headers() {
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        let app = create_router(HashMap::new(), sensors);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register_sensor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_invalid_method() {
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        let app = create_router(HashMap::new(), sensors);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/register_sensor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn register_non_extant_user() {
        let (mut signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key);
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        let app = create_router(hashmap, sensors);

        let signature = signing_key.sign(b"junk_data");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register_sensor")
                    .header("user", "nontestUser")
                    .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn deregister_missing_headers() {
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        let app = create_router(HashMap::new(), sensors);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/deregister_sensor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deregister_invalid_method() {
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        let app = create_router(HashMap::new(), sensors);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/deregister_sensor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn deregister_non_extant_user() {
        let (mut signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key);
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        let app = create_router(hashmap, sensors);

        let signature = signing_key.sign(b"junk_data");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/deregister_sensor")
                    .header("user", "nontestUser")
                    .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deregister_non_extant_sensor() {
        let (mut signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key);
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        let app = create_router(hashmap, sensors);

        let body = serde_json::to_string(&Sensor::new("testSensor".to_owned(), [0u8; 16])).unwrap();

        let signature = signing_key.sign(body.as_bytes());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/deregister_sensor")
                    .header("user", "testUser")
                    .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn happy_path() {
        let (mut signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8080").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let body = serde_json::to_string(&Sensor::new("testSensor".to_owned(), [0u8; 16])).unwrap();

        let signature = signing_key.sign(body.as_bytes());

        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost:8080/register_sensor")
            .header("user", "testUser")
            .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = client
            .post("http://localhost:8080/deregister_sensor")
            .header("user", "testUser")
            .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
