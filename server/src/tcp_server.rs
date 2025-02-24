use crate::Sensor;
use aes::Aes128;
use ccm::consts::{U10, U13};
use ccm::{Ccm, KeyInit};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

pub type Aes128Ccm = Ccm<Aes128, U10, U13>;

pub async fn serve(data_listener: TcpListener, sensors: Arc<RwLock<HashMap<String, Sensor>>>) {
    loop {
        if let Ok((stream, socket)) = data_listener.accept().await {
            tokio::spawn(handle_data_client(stream, socket, sensors.clone()));
        }
    }
}

async fn handle_data_client(
    stream: TcpStream,
    _socket: SocketAddr,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
) {
    let (rx, tx) = stream.into_split();

    let mut reader = BufReader::new(rx);
    let _writer = BufWriter::new(tx);

    loop {
        // read sensor name
        let mut buffer: Vec<u8> = Vec::new();
        let Ok(_) = reader.read_until('|' as u8, &mut buffer).await else {
            // Invalid format, drop the connection
            return;
        };

        println!("{:?}", buffer);

        buffer.pop().unwrap();
        let _cipher: Aes128Ccm;
        let Ok(name) = String::from_utf8(buffer) else {
            // Invalid format, drop the connection
            return;
        };

        {
            // read lock scope
            let read_lock = sensors.read().await;
            let Some(sensor) = read_lock.get(&name) else {
                // no sensor with that name registered, drop the connection
                return;
            };

            _cipher = Aes128Ccm::new_from_slice(&sensor.key).unwrap();
        }

        // read encrypted packet length
        let mut buffer: Vec<u8> = Vec::new();
        let Ok(bytes) = reader.read_until('|' as u8, &mut buffer).await else {
            // Invalid format, drop the connection
            return;
        };
        if bytes != 2 {
            // invalid format, drop the connection
            return;
        }
        let len: u8 = buffer[1];

        // read encrypted data
        let mut nonce: Vec<u8> = vec![0; len as usize];
        let Ok(_) = reader.read_exact(&mut nonce[..]).await else {
            // data read failure, drop the connection
            return;
        };
        // let enc_data = nonce.split_off(13);

        // let Ok(dec_data) = cipher.decrypt(GenericArray::from_slice(&nonce), &enc_data[..]) else {
        //     // decryption failed, drop the connection
        //     return;
        // };

        // let Ok(value): Result<Value, _> = serde_json::from_slice(&dec_data) else {
        //     // unexpected data packet, drop the connection
        //     return;
        // };

        println!("{}", String::from_utf8(nonce).unwrap());
    }
}

#[cfg(test)]
mod test {
    #[tokio::test]
    async fn happy_path() {}
}
