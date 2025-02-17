use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn serve(data_listener: TcpListener) {
    loop {
        if let Ok((stream, socket)) = data_listener.accept().await {
            tokio::spawn(handle_data_client(stream, socket));
        }
    }
}

async fn handle_data_client(mut stream: TcpStream, _socket: SocketAddr) {
    let mut buf = vec![0; 1024];
    let mut prev_buf = vec![0; 1024];

    stream
        .write("Welcome. I hope you are ready.\n".as_bytes())
        .await
        .expect("failed to write to socket");

    loop {
        let n = stream
            .read(&mut buf)
            .await
            .expect("failed to read from socket");

        if n == 0 {
            return;
        }

        stream
            .write_all(&prev_buf)
            .await
            .expect("failed to write to socket");

        std::mem::swap(&mut buf, &mut prev_buf);
    }
}
