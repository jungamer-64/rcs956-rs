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
            let mut message = error.to_string();
            let mut cause = error.source();
            while let Some(error) = cause {
                message.push_str(": ");
                message.push_str(&error.to_string());
                cause = error.source();
            }
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}
