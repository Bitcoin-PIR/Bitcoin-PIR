use std::env;
use std::ffi::CString;
use std::os::raw::{c_int, c_long};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;

const AT_FDCWD: c_int = -100;
const RENAME_NOREPLACE: u32 = 1;

#[cfg(all(target_os = "linux", target_arch = "x86_64", not(payment_v1_test_force_enosys)))]
const SYS_RENAMEAT2: c_long = 316;

#[cfg(all(target_os = "linux", target_arch = "x86_64", payment_v1_test_force_enosys))]
const SYS_RENAMEAT2: c_long = -1;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

fn main() -> ExitCode {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        eprintln!("renameat2-noreplace: expected SOURCE and DESTINATION");
        return ExitCode::FAILURE;
    }
    let source_path = Path::new(&arguments[0]);
    let destination_path = Path::new(&arguments[1]);
    if !source_path.is_absolute()
        || !destination_path.is_absolute()
        || source_path == destination_path
        || source_path.parent() != destination_path.parent()
    {
        eprintln!("renameat2-noreplace: paths must be distinct absolute siblings");
        return ExitCode::FAILURE;
    }
    let Ok(source) = CString::new(arguments[0].as_bytes()) else {
        eprintln!("renameat2-noreplace: source contains a NUL byte");
        return ExitCode::FAILURE;
    };
    let Ok(destination) = CString::new(arguments[1].as_bytes()) else {
        eprintln!("renameat2-noreplace: destination contains a NUL byte");
        return ExitCode::FAILURE;
    };

    // SAFETY: both path pointers are valid NUL-terminated byte strings for the
    // duration of the call. The fixed Linux/amd64 syscall and flag provide the
    // atomic no-replace property; ENOSYS and every other error fail closed.
    let result = unsafe {
        syscall(
            SYS_RENAMEAT2,
            AT_FDCWD,
            source.as_ptr(),
            AT_FDCWD,
            destination.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        eprintln!(
            "renameat2-noreplace: atomic publication refused: {}",
            std::io::Error::last_os_error(),
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
