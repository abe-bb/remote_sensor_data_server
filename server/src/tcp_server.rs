use crate::Sensor;
use aes::Aes128;
use ccm::aead::generic_array::GenericArray;
use ccm::aead::Aead;
use ccm::consts::{U13, U4};
use ccm::{Ccm, KeyInit};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{event, instrument, Level};

pub type Aes128Ccm = Ccm<Aes128, U4, U13>;

#[instrument(skip_all)]
pub async fn serve(data_listener: TcpListener, sensors: Arc<RwLock<HashMap<String, Sensor>>>) {
    loop {
        match data_listener.accept().await {
            Ok((stream, socket)) => {
                event!(Level::INFO, "Accepting TCP connection: {}", socket);
                tokio::spawn(handle_data_client(stream, socket, sensors.clone()));
            }
            Err(e) => {
                event!(Level::ERROR, "TCP connection error: {}", e);
            }
        }
    }
}

#[instrument(skip_all)]
async fn handle_data_client(
    stream: TcpStream,
    socket: SocketAddr,
    sensors: Arc<RwLock<HashMap<String, Sensor>>>,
) {
    let (rx, tx) = stream.into_split();

    let mut reader = BufReader::new(rx);
    let _writer = BufWriter::new(tx);

    loop {
        // read until start of known protocol
        let mut start: Vec<u8> = Vec::new();
        let Ok(len) = reader.read_until(b'>', &mut start).await else {
            event!(
                Level::WARN,
                "Failed to find data transfer sensor data protocol start. Closing connection: {}",
                socket
            );
            return;
        };
        if len == 0 {
            event!(Level::INFO, "Connection closed by client");
            return;
        }
        if start.len() > 1 {
            event!(
                Level::INFO,
                "Read {} bytes without finding sensor data protocol start",
                start.len() - 1
            );
        }
        start.clear();

        // read sensor name
        let Ok(len) = reader.read_until(b'<', &mut start).await else {
            event!(
                Level::WARN,
                "Failed to find end of sensor name. Closing connection: {}",
                socket
            );
            return;
        };
        if len == 0 {
            event!(Level::INFO, "Connection closed by client");
            return;
        }

        // decode sensor name
        start.pop().unwrap();
        let Ok(name) = String::from_utf8(start) else {
            event!(
                Level::WARN,
                "Sensor name recieved from {} was not valid UTF-8",
                socket
            );
            continue;
        };
        event!(Level::DEBUG, "Read sensor name: {} from {}", name, socket);

        // read counter
        let mut counter: [u8; 5] = [0; 5];
        for i in 0..5 {
            let Ok(byte) = reader.read_u8().await else {
                event!(
                    Level::WARN,
                    "failed to read counter. Closing connection: {}",
                    socket
                );
                return;
            };
            counter[i] = byte;
        }

        // read encrypted packet size
        let Ok(encrypted_packet_size) = reader.read_u8().await else {
            event!(
                Level::WARN,
                "failed to read encrypted packet size. Closing connection: {}",
                socket
            );
            return;
        };

        // read encrypted packet
        let mut encrypted_packet: Vec<u8> = vec![0u8; encrypted_packet_size as usize];
        let Ok(_) = reader.read_exact(&mut encrypted_packet).await else {
            event!(
                Level::WARN,
                "failed to read encrypted packet. Closing connection: {}",
                socket
            );
            return;
        };

        let cipher: Aes128Ccm;
        let nonce: GenericArray<u8, ccm::consts::U13>;

        {
            // read lock scope
            let read_lock = sensors.read().await;
            let Some(sensor) = read_lock.get(&name) else {
                event!(
                    Level::WARN,
                    "sensor \"{}\" is not a known sensor. Dropping connection: {}",
                    name,
                    socket
                );
                return;
            };

            nonce = sensor.ccm_data.get_nonce(counter);
            cipher = Aes128Ccm::new_from_slice(&sensor.key).unwrap();
        }
        let decrypted_packet = cipher.decrypt(&nonce, encrypted_packet.as_slice());

        match decrypted_packet {
            Ok(bytes) => {
                event!(
                    Level::INFO,
                    "Decrypted packet: {}",
                    String::from_utf8(bytes).unwrap()
                )
            }
            Err(e) => {
                event!(
                    Level::WARN,
                    "Failed to decypted packet from: {}. Error: {}",
                    socket,
                    e
                );
            }
        }

        // // read encrypted packet length
        // let mut buffer: Vec<u8> = Vec::new();
        // let Ok(bytes) = reader.read_until('|' as u8, &mut buffer).await else {
        //     // Invalid format, drop the connection
        //     return;
        // };
        // if bytes != 2 {
        //     // invalid format, drop the connection
        //     return;
        // }
        // let len: u8 = buffer[1];

        // // read encrypted data
        // let mut nonce: Vec<u8> = vec![0; len as usize];
        // let Ok(_) = reader.read_exact(&mut nonce[..]).await else {
        //     // data read failure, drop the connection
        //     return;
        // };
        // let enc_data = nonce.split_off(13);

        // let Ok(dec_data) = cipher.decrypt(GenericArray::from_slice(&nonce), &enc_data[..]) else {
        //     // decryption failed, drop the connection
        //     return;
        // };

        // let Ok(value): Result<Value, _> = serde_json::from_slice(&dec_data) else {
        //     // unexpected data packet, drop the connection
        //     return;
        // };

        // println!("{}", String::from_utf8(nonce).unwrap());
    }
}

#[cfg(test)]
mod test {
    #[tokio::test]
    async fn happy_path() {}
}
