//! Command-line entry point for RC-S956.
#![deny(unsafe_code)]

mod command;

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Windows USB and device enumeration ABI is isolated in this module"
)]
mod windows;

fn main() -> std::process::ExitCode {
    match command::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
