#![no_main]
#![no_std]

use cortex_m_rt::entry;
use embedded_hal::{delay::DelayNs, digital::OutputPin};
use microbit::{
    hal::{Timer, Uarte},
    Board,
};
use panic_halt as _;
use rtt_target::{rprintln, rtt_init_print};

#[entry]
fn main() -> ! {
    rtt_init_print!();
    let mut board = Board::take().unwrap();

    let mut timer = Timer::new(board.TIMER0);

    let serial = Uarte::new(
        board.UARTE0,
        board.uart.into(),
        microbit::hal::uarte::Parity::INCLUDED,
        microbit::hal::uarte::Baudrate::BAUD115200,
    );

    board.display_pins.col1.set_low().unwrap();
    board.display_pins.col5.set_low().unwrap();
    let mut row1 = board.display_pins.row1;
    loop {
        row1.set_low().unwrap();
        rprintln!("Dark!");
        timer.delay_ms(1_000);
        row1.set_high().unwrap();
        rprintln!("Light!");
        timer.delay_ms(1_000);
    }
}
