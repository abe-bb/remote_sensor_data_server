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
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

const RSA_SIZE: usize = 2048;

fn create_router(authorized_users: HashMap<String, VerifyingKey<Sha256>>) -> Router {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, RSA_SIZE).expect("Couldn't generate rsa key");
    let pub_key = RsaPublicKey::from(&priv_key);

    // tmp
    let test = b"hello world :)";
    println!(
        "{}",
        pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap()
    );
    let signature_key = SigningKey::<Sha256>::new(priv_key.clone());
    let signature = signature_key.sign_with_rng(&mut rng, test);
    println!("{:?}", signature.to_bytes());
    // tmp

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

    app
}

pub async fn start(
    tcp_listener: TcpListener,
    authorized_users: HashMap<String, VerifyingKey<Sha256>>,
) {
    let app = create_router(authorized_users);
    axum::serve(tcp_listener, app).await.unwrap();
}

async fn register_sensor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // check for appropriate headers
    if !(headers.contains_key("user")
        && headers.contains_key("encrypted_key")
        && headers.contains_key("signature"))
    {
        return StatusCode::BAD_REQUEST;
    }

    let (user_header, key_header, signature_header) = (
        headers.get("user").unwrap(),
        headers.get("encrypted_key").unwrap(),
        headers.get("signature").unwrap(),
    );

    // check for valid user, signature, and key
    let Ok(user) = user_header.to_str() else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(encrypted_key) = key_header.to_str() else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(signature) = signature_header.to_str() else {
        return StatusCode::BAD_REQUEST;
    };

    // convert from Base64 to binary
    let Ok(encrypted_key) = BASE64_STANDARD.decode(encrypted_key) else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(signature) = BASE64_STANDARD.decode(signature) else {
        return StatusCode::BAD_REQUEST;
    };

    // construct signature from binary
    let Ok(signature) = Signature::try_from(&signature[..]) else {
        return StatusCode::BAD_REQUEST;
    };

    // check that the user exists
    if !state.authorized_users.contains_key(user) {
        return StatusCode::UNAUTHORIZED;
    }

    let user_verification_key = state.authorized_users.get(user).unwrap();
    let body = body.to_vec();

    // check that signature matches declared user
    let Err(_) = user_verification_key.verify(&body[..], &signature) else {
        return StatusCode::UNAUTHORIZED;
    };

    // decrypt symmetric key
    let dec_data = state
        .server_private_key
        .decrypt(Pkcs1v15Encrypt, key_header.as_bytes());

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
    authorized_users: HashMap<String, VerifyingKey<Sha256>>,
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

#[cfg(test)]
mod test {
    use super::*;
    use axum::{body::Body, http::Request};
    use rsa::pkcs1::DecodeRsaPublicKey;
    use tower::ServiceExt;

    fn create_user_data() -> ([u8; 256], VerifyingKey<Sha256>) {
        let signature: [u8; 256] = [
            191, 192, 10, 226, 178, 177, 129, 82, 158, 43, 36, 185, 106, 65, 243, 34, 216, 95, 33,
            35, 6, 86, 110, 26, 159, 151, 218, 247, 186, 45, 215, 36, 140, 34, 71, 215, 154, 166,
            75, 21, 132, 215, 154, 168, 122, 93, 179, 152, 238, 5, 198, 16, 87, 116, 34, 13, 2,
            153, 249, 194, 211, 121, 145, 6, 217, 77, 187, 69, 218, 210, 47, 211, 221, 68, 37, 35,
            40, 45, 181, 57, 183, 241, 188, 23, 13, 23, 74, 34, 237, 219, 13, 71, 225, 73, 175,
            120, 47, 129, 174, 53, 147, 38, 206, 108, 143, 150, 189, 75, 164, 240, 179, 57, 72,
            115, 201, 47, 65, 124, 6, 188, 234, 16, 214, 126, 138, 243, 67, 163, 182, 215, 13, 208,
            99, 194, 72, 99, 213, 55, 220, 0, 66, 217, 160, 55, 213, 39, 247, 120, 214, 36, 177,
            136, 213, 229, 127, 190, 195, 136, 185, 196, 231, 178, 108, 177, 87, 84, 207, 224, 109,
            40, 178, 114, 56, 97, 138, 250, 236, 66, 85, 187, 59, 94, 254, 107, 91, 146, 196, 201,
            222, 9, 195, 145, 225, 45, 102, 192, 41, 150, 47, 57, 93, 133, 122, 100, 192, 242, 7,
            27, 62, 165, 177, 215, 94, 132, 18, 98, 126, 66, 13, 22, 72, 138, 123, 98, 234, 8, 230,
            23, 246, 63, 1, 26, 123, 59, 155, 56, 208, 237, 140, 194, 203, 229, 168, 64, 168, 113,
            59, 109, 33, 83, 45, 247, 32, 100, 174, 75,
        ];
        let user_pub_key: RsaPublicKey = RsaPublicKey::from_pkcs1_pem(
            "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA0bopqNmou2tnYQi6E+D3gFxPUej/cruuR/F6luI6ve6H1dQVL8qF
+obkS31QQau7/oD0g9r4jI4iVmn6gXLiyrQwgNqSz3p86eN89PtLMBV/QgvBUNEU
fRzQZRdW9Ofg2yvx26r+8ybxuZ+b+uFqNT4/H0iCchVka4PpLJqROEjEdkAdjUP6
HQ72YOUAry1o+3mGXB+AhlvbiJIPissE+HZBde63X8GMfdjT98eJBTVRNddxmaBL
Lex6udaVpJ72SURT1gL80WUdJoAhN+IL6hGzmiHnn5pFDxrW7aRdkQwXy9CYsAzx
GtkdvVdegW8AZE4+64ZGNSWNd8Qi2tqQlwIDAQAB
-----END RSA PUBLIC KEY-----",
        )
        .unwrap();

        (signature, user_pub_key.into())
    }

    #[tokio::test]
    async fn missing_headers() {
        let app = create_router(HashMap::new());

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
    async fn invalid_method() {
        let app = create_router(HashMap::new());

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
    async fn non_extant_user() {
        let (signature, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key);
        let app = create_router(hashmap);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register_sensor")
                    .header("user", "nontestUser")
                    .header("signature", BASE64_STANDARD.encode(signature))
                    .header("encrypted_key", "junk")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn happy_path() {
        let (signature, verifying_key) = create_user_data();
        let mut hashmap = HashMap::new();
        hashmap.insert("testUser".to_owned(), verifying_key);

        let listener = TcpListener::bind("localhost:80").await.unwrap();
        tokio::spawn(start(listener, hashmap));

        let response = reqwest::get("http://localhost/server_public_key")
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        let server_pub_key = RsaPublicKey::from_pkcs1_pem(&response).unwrap();

        // TODO: finish test

        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost/register_sensor")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
