#![no_main]
#![no_std]

use core::fmt::{self, Write};

use cortex_m_rt::entry;
use heapless::{String, Vec};
use lsm303agr::{AccelOutputDataRate, Lsm303agr};
use microbit::{
    hal::{twim, uarte, Timer, Uarte},
    Board,
};
use panic_halt as _;
use rtt_target::{rprintln, rtt_init_print};

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

    loop {
        if let Ok(status) = accel_sensor.accel_status() {
            if status.xyz_new_data() {
                let data = accel_sensor.acceleration().unwrap();
                let (x, y, z) = data.xyz_mg();
                let msg = build_msg(x, y, z);
                rprintln!("message: {}", msg);
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

fn build_msg(x: i32, y: i32, z: i32) -> String<251> {
    let mut data: String<251> = String::new();
    write!(
        &mut data,
        "{{\"name\": \"example_sensor\", \"accel_x\": {}, \"accel_y\": {}, \"accel_z\": {}}}",
        x, y, z
    )
    .unwrap();

    data
}
