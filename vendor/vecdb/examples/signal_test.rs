use std::{thread, time::Duration};
use vecdb::Exit;

fn main() {
    let exit = Exit::new();
    exit.register_cleanup(|| {
        eprintln!("[cleanup] flushing data...");
    });
    exit.set_ctrlc_handler();

    eprintln!("Running... press Ctrl+C to test signal handling");
    for i in 1.. {
        let _lock = exit.lock();
        eprintln!("  tick {i}");
        thread::sleep(Duration::from_secs(1));
    }
}
