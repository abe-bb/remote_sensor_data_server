use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    body::Bytes,
    debug_handler,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};

use base64::{prelude::BASE64_STANDARD, Engine};
use rand::Rng;
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    sha2::Sha256,
    signature::Verifier,
    RsaPrivateKey, RsaPublicKey,
};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{event, instrument, Level};

use crate::Sensor;

const RSA_SIZE: usize = 2048;
const CHALLENGE_SIZE: usize = 64;

fn create_router(
    authorized_users: HashMap<String, VerifyingKey<Sha256>>,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
) -> Router {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, RSA_SIZE).expect("Couldn't generate rsa key");
    let pub_key = RsaPublicKey::from(&priv_key);
    // let (priv_key, pub_key) = create_server_data();

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!\n" }))
        .route("/challenge/{user}", get(challenge))
        .route("/register_sensor", post(register_sensor))
        .route("/deregister_sensor", post(deregister_sensor))
        .route("/server_public_key", get(server_public_key))
        .with_state(Arc::new(AppState {
            authorized_users,
            user_challenges: RwLock::new(HashMap::new()),
            server_public_key: pub_key,
            _server_private_key: priv_key,
            sensors,
        }));

    app
}

pub async fn start(
    tcp_listener: TcpListener,
    authorized_users: HashMap<String, VerifyingKey<Sha256>>,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
) {
    let app = create_router(authorized_users, sensors);
    let app = app.into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(tcp_listener, app).await.unwrap();
}

#[instrument(skip_all)]
#[debug_handler]
async fn challenge(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(user): Path<String>,
    State(state): State<Arc<AppState>>,
) -> [u8; CHALLENGE_SIZE] {
    // generate challenge response
    let mut challenge = [0; CHALLENGE_SIZE];
    {
        let mut rng = rand::thread_rng();
        rng.fill(&mut challenge);
    }

    // check if use exists
    if !state.authorized_users.contains_key(&user) {
        event!(
            Level::WARN,
            "{} requested challenge for non-existant user \"{}\"",
            addr.ip(),
            user
        );
    } else {
        event!(
            Level::INFO,
            "{} requested challenge for authorized user \"{}\"",
            addr.ip(),
            user
        );

        // update user challenge
        let mut user_challenges = state.user_challenges.write().await;
        user_challenges.insert(user, challenge.clone());
    } // write lock scope ends
    challenge
}

#[instrument(skip(state, headers, body))]
async fn register_sensor(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (status, sensor) = authenticate_and_parse_sensor(
        headers,
        body,
        &state.authorized_users,
        &state.user_challenges,
    )
    .await;

    let Some(sensor) = sensor else {
        return status;
    };

    // scope for write access to hashmap
    {
        let mut write_lock = state.sensors.write().await;
        // check if sensor name is already taken
        if write_lock.contains_key(&sensor.name) {
            event!(
                Level::WARN,
                "sensor {} already registered! Registration failed.",
                sensor.name
            );
            return StatusCode::CONFLICT;
        }

        event!(
            Level::INFO,
            "sensor {} succesfully registered!",
            sensor.name
        );
        // add new sensor
        write_lock.insert(sensor.name.clone(), sensor);
    }; // write lock dropped

    StatusCode::OK
}

#[instrument(skip(state, headers, body))]
async fn deregister_sensor(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (status, sensor) = authenticate_and_parse_sensor(
        headers,
        body,
        &state.authorized_users,
        &state.user_challenges,
    )
    .await;

    let Some(sensor) = sensor else {
        return status;
    };

    // scope for write access to hashmap
    {
        let mut write_lock = state.sensors.write().await;
        if let Some(_) = write_lock.remove(&sensor.name) {
            event!(
                Level::INFO,
                "sensor {} succesfully deregistered!",
                sensor.name
            );
            StatusCode::OK
        } else {
            event!(
                Level::WARN,
                "sensor {} not removed because it was not registered",
                sensor.name
            );
            StatusCode::NOT_FOUND
        }
    } // write lock dropped
}

#[instrument(skip(state))]
async fn server_public_key(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> String {
    event!(Level::INFO, "{} requested server's public key", addr.ip());

    state
        .server_public_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
}

#[instrument(skip_all)]
async fn authenticate_and_parse_sensor(
    headers: HeaderMap,
    body: Bytes,
    authorized_users: &HashMap<String, VerifyingKey<Sha256>>,
    user_challenges: &RwLock<HashMap<String, [u8; CHALLENGE_SIZE]>>,
) -> (StatusCode, Option<Sensor>) {
    // check for appropriate headers
    if !(headers.contains_key("user")
        && headers.contains_key("signature")
        && headers.contains_key("key")
        && headers.contains_key("challenge"))
    {
        event!(Level::INFO, "Invalid header format");
        return (StatusCode::BAD_REQUEST, None);
    }

    let (user_header, signature_header, key_header, challenge_header) = (
        headers.get("user").unwrap(),
        headers.get("signature").unwrap(),
        headers.get("key").unwrap(),
        headers.get("challenge").unwrap(),
    );

    // check for valid user, signature, and key format
    let Ok(user) = user_header.to_str() else {
        event!(Level::INFO, "invalid user header. Not UTF-8");
        return (StatusCode::BAD_REQUEST, None);
    };
    let Ok(signature) = signature_header.to_str() else {
        event!(Level::INFO, "invalid signature header. Not UTF-8");
        return (StatusCode::BAD_REQUEST, None);
    };
    let Ok(_key) = key_header.to_str() else {
        event!(Level::INFO, "invalid key header. Not UTF-8");
        return (StatusCode::BAD_REQUEST, None);
    };
    let Ok(challenge) = challenge_header.to_str() else {
        event!(Level::INFO, "invalid key header. Not UTF-8");
        return (StatusCode::BAD_REQUEST, None);
    };

    // check that the user exists
    if !authorized_users.contains_key(user) {
        event!(Level::WARN, "Recieved request from unknown user");
        return (StatusCode::UNAUTHORIZED, None);
    }

    // Construct challenge signature
    let Ok(challenge) = BASE64_STANDARD.decode(challenge) else {
        event!(Level::INFO, "invalid challenge. Not base64 encoded");
        return (StatusCode::BAD_REQUEST, None);
    };
    let Ok(challenge) = Signature::try_from(&challenge[..]) else {
        event!(Level::INFO, "invalid challenge signature");
        return (StatusCode::BAD_REQUEST, None);
    };

    // Verify that the challenge signature matches expected value
    let user_verification_key = authorized_users.get(user).unwrap();
    {
        // read lock scope
        let challenges = user_challenges.read().await;
        if !challenges.contains_key(user) {
            event!(
                Level::INFO,
                "{} attempted request without active challenge",
                user
            );
            return (StatusCode::FORBIDDEN, None);
        }

        let Ok(_) = user_verification_key.verify(challenges.get(user).unwrap(), &challenge) else {
            // user challenge failed
            event!(Level::WARN, "{} failed challenge verification", user);
            return (StatusCode::FORBIDDEN, None);
        };
    } // end of read lock scope

    // Construct signature
    let Ok(signature) = BASE64_STANDARD.decode(signature) else {
        event!(Level::INFO, "invalid signature. Not base64 encoded");
        return (StatusCode::BAD_REQUEST, None);
    };
    let Ok(signature) = Signature::try_from(&signature[..]) else {
        event!(Level::INFO, "invalid signature");
        return (StatusCode::BAD_REQUEST, None);
    };

    // check that signature matches declared user
    let Ok(_) = user_verification_key.verify(&body[..], &signature) else {
        event!(
            Level::WARN,
            "message body signature verification failed for {}",
            user
        );
        return (StatusCode::UNAUTHORIZED, None);
    };

    // Deserialize sensor from body
    let Ok(sensor): Result<Sensor, _> = serde_json::from_slice(&body) else {
        event!(
            Level::INFO,
            "Failed to deserialized sensor for authenticated user {}",
            user
        );
        return (StatusCode::BAD_REQUEST, None);
    };

    (StatusCode::OK, Some(sensor))
}

fn _user_data() -> (RsaPrivateKey, RsaPublicKey) {
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

    (user_priv_key, user_pub_key)
}

struct AppState {
    authorized_users: HashMap<String, VerifyingKey<Sha256>>,
    user_challenges: RwLock<HashMap<String, [u8; CHALLENGE_SIZE]>>,
    server_public_key: RsaPublicKey,
    _server_private_key: RsaPrivateKey,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use rsa::{
        pkcs1v15::SigningKey,
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        signature::{SignatureEncoding, SignerMut},
    };

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
        let (mut _signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8090").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost:8090/register_sensor")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_invalid_method() {
        let (mut _signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8089").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let client = reqwest::Client::new();
        let response = client
            .get("http://localhost:8089/register_sensor")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn register_non_extant_user() {
        let (mut _signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8081").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost:8081/register_sensor")
            .header("user", "nontestUser")
            .header("signature", "junk")
            .header("key", "junk")
            .header("challenge", "junk")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deregister_missing_headers() {
        let (mut _signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8082").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost:8082/deregister_sensor")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deregister_invalid_method() {
        let (mut _signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8083").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let client = reqwest::Client::new();
        let response = client
            .get("http://localhost:8083/deregister_sensor")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn deregister_non_extant_user() {
        let (mut _signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8091").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost:8091/deregister_sensor")
            .header("user", "nonexistant")
            .header("signature", "junk")
            .header("challenge", "junk")
            .header("key", "junk")
            .send()
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

        let body =
            serde_json::to_string(&Sensor::new("testSensor".to_owned(), [0u8; 16], [0; 8], 1))
                .unwrap();

        let signature = signing_key.sign(body.as_bytes());

        let listner = TcpListener::bind("localhost:8093").await.unwrap();
        tokio::spawn(start(listner, hashmap, sensors));

        let client = reqwest::Client::new();
        let challenge_response = client
            .get("http://localhost:8093/challenge/testUser")
            .send()
            .await
            .unwrap();
        let challenge = challenge_response.bytes().await.unwrap();
        let challenge_signature = signing_key.sign(&challenge);

        let response = client
            .post("http://localhost:8093/deregister_sensor")
            .header("user", "testUser")
            .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
            .header(
                "challenge",
                BASE64_STANDARD.encode(challenge_signature.to_bytes()),
            )
            .header("key", "junk")
            .body(body)
            .send()
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

        let body =
            serde_json::to_string(&Sensor::new("testSensor".to_owned(), [0u8; 16], [0; 8], 1))
                .unwrap();

        let signature = signing_key.sign(body.as_bytes());

        let client = reqwest::Client::new();
        let challenge_response = client
            .get("http://localhost:8080/challenge/testUser")
            .send()
            .await
            .unwrap();
        let challenge = challenge_response.bytes().await.unwrap();
        let challenge_signature = signing_key.sign(&challenge);

        let response = client
            .post("http://localhost:8080/register_sensor")
            .header("user", "testUser")
            .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
            .header("key", "junk")
            .header(
                "challenge",
                BASE64_STANDARD.encode(challenge_signature.to_bytes()),
            )
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let challenge_response = client
            .get("http://localhost:8080/challenge/testUser")
            .send()
            .await
            .unwrap();
        let challenge = challenge_response.bytes().await.unwrap();
        let challenge_signature = signing_key.sign(&challenge);

        let response = client
            .post("http://localhost:8080/deregister_sensor")
            .header("user", "testUser")
            .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
            .header("key", "junk")
            .header(
                "challenge",
                BASE64_STANDARD.encode(challenge_signature.to_bytes()),
            )
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn no_active_user_challenge() {
        let (mut signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8094").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let body =
            serde_json::to_string(&Sensor::new("testSensor".to_owned(), [0u8; 16], [0; 8], 1))
                .unwrap();

        let signature = signing_key.sign(body.as_bytes());

        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost:8094/register_sensor")
            .header("user", "testUser")
            .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
            .header("key", "junk")
            .header("challenge", BASE64_STANDARD.encode(b"junk data"))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn incorrect_user_challenge() {
        let (mut signing_key, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key.clone());

        let listener = TcpListener::bind("localhost:8095").await.unwrap();
        let sensors = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(start(listener, hashmap, sensors));

        let body =
            serde_json::to_string(&Sensor::new("testSensor".to_owned(), [0u8; 16], [0; 8], 1))
                .unwrap();

        let signature = signing_key.sign(body.as_bytes());

        let client = reqwest::Client::new();
        let _challenge_response = client
            .get("http://localhost:8095/challenge/testUser")
            .send()
            .await
            .unwrap();

        let response = client
            .post("http://localhost:8095/register_sensor")
            .header("user", "testUser")
            .header("signature", BASE64_STANDARD.encode(signature.to_bytes()))
            .header("key", "junk")
            .header("challenge", BASE64_STANDARD.encode(b"junk data"))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
