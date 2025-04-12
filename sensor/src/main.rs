#![no_main]
#![no_std]

use core::fmt::Write;

use base64::{prelude::BASE64_STANDARD, Engine};
use cortex_m_rt::entry;
use heapless::{String, Vec};
use lsm303agr::{AccelOutputDataRate, Lsm303agr};
use microbit::{
    hal::{ccm::CcmData, twim, uarte, Ccm, Timer, Uarte},
    Board,
};
use panic_halt as _;
use rtt_target::{rprintln, rtt_init_print};

const MIC_SIZE: u8 = 4;
const HEADER_SIZE: u8 = 3;

#[entry]
fn main() -> ! {
    rtt_init_print!();
    let board = Board::take().unwrap();

    let mut timer = Timer::new(board.TIMER0);
    let mut accel_delay_timer = Timer::new(board.TIMER2);

    let mut serial = Uarte::new(
        board.UARTE0,
        board.uart.into(),
        microbit::hal::uarte::Parity::EXCLUDED,
        microbit::hal::uarte::Baudrate::BAUD115200,
    );

    let i2c = twim::Twim::new(
        board.TWIM0,
        board.i2c_internal.into(),
        twim::Frequency::K100,
    );
    let mut accel_sensor = Lsm303agr::new_with_i2c(i2c);
    accel_sensor.init().unwrap();
    accel_sensor
        .set_accel_mode_and_odr(
            &mut accel_delay_timer,
            lsm303agr::AccelMode::LowPower,
            AccelOutputDataRate::Hz1,
        )
        .unwrap();

    let mut read_buf = [0u8; 128];

    let mut ccm = Ccm::init(board.CCM, board.AAR, microbit::hal::ccm::DataRate::_1Mbit);
    let init_vec: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    let mut ccm_data = CcmData::new(
        [
            0xfd, 0xa4, 0x92, 0xea, 0x96, 0xad, 0xb6, 0x44, 0x8b, 0xc3, 0x74, 0xd7, 0x1a, 0x53,
            0x52, 0x52,
        ],
        init_vec.clone(),
    );

    let mut counter: u64 = 0;

    loop {
        if let Ok(status) = accel_sensor.accel_status() {
            if status.xyz_new_data() {
                let data = accel_sensor.acceleration().unwrap();
                let (x, y, z) = data.xyz_mg();
                let data = build_data(x, y, z);
                rprintln!("Accel Data: {}", data);

                let encrypted_data = encrypt_data(&mut counter, &mut ccm, data, &mut ccm_data);

                write!(serial, ">example_sensor<").unwrap();
                serial.write(&(counter - 1).to_le_bytes()[..]).unwrap();
                serial.write(&encrypted_data[1..2]).unwrap();
                serial.write(&encrypted_data[3..]).unwrap();
            }
        } else {
            rprintln!("couldn't check accelerometer status");
        }

        match serial.read_timeout(&mut read_buf, &mut timer, 1000) {
            Ok(_) => rprintln!("recieved: {:?}", &read_buf),
            Err(uarte::Error::Timeout(n)) => {
                if n > 0 {
                    rprintln!("recieved bytes: {:?}", &read_buf[..n]);
                }
            }
            Err(e) => {
                rprintln!("recieved_error: {:?}", e)
            }
        }
    }
}

fn build_data(x: i32, y: i32, z: i32) -> String<251> {
    let mut data: String<251> = String::new();
    write!(
        &mut data,
        "{{\"accel_x\": {}, \"accel_y\": {}, \"accel_z\": {}}}",
        x, y, z
    )
    .unwrap();

    data
}

fn encrypt_data(
    counter: &mut u64,
    ccm: &mut Ccm,
    data: String<251>,
    ccm_data: &mut CcmData,
) -> Vec<u8, 258> {
    let len: u8 = data.len() as u8;
    let mut scratch: Vec<u8, 274> = Vec::new();
    for _ in 0..16 {
        scratch.push(0).unwrap();
    }

    let _nonce: [u8; 16] = [0; 16];

    let mut ciphertext = Vec::<u8, 258>::new();
    for _ in 0..(data.len() as u8 + HEADER_SIZE + MIC_SIZE) {
        scratch.push(0).unwrap();
        ciphertext.push(0).unwrap();
    }

    while scratch.len() < 43 {
        scratch.push(0).unwrap();
    }

    let mut cleartext: Vec<u8, 254> = Vec::new();
    cleartext.push(0).unwrap();
    cleartext.push(len).unwrap();
    cleartext.push(0).unwrap();
    cleartext.extend(data.into_bytes().into_iter());

    if let Err(e) = ccm.encrypt_packet(ccm_data, &cleartext, &mut ciphertext, &mut scratch) {
        rprintln!("Encryption Error: {:?}", e);
    } else {
        *counter += 1;
    }

    ciphertext
}
