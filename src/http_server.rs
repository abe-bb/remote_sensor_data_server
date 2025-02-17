use axum::{
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;

pub async fn serve(tcp_listener: TcpListener) {
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/register_sensor", post(register_sensor))
        .route("/deregister_sensor", post(deregister_sensor));

    axum::serve(tcp_listener, app).await.unwrap();
}

async fn register_sensor() {}
async fn deregister_sensor() {}
