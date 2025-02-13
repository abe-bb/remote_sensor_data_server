use axum::{
    routing::{get, post},
    Router,
};
#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register_sensor", post(register_sensor))
        .route("/deregister_sensor", post(deregister_sensor));

    let http_listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    let data_listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();

    axum::serve(http_listener, app).await.unwrap();
}

async fn register_sensor() {}
async fn deregister_sensor() {}
