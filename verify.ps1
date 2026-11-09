$ErrorActionPreference = 'Stop'
$savedRustdocFlags = $env:RUSTDOCFLAGS
Push-Location $PSScriptRoot
try {
    cargo fmt --all --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting failed' }
    cargo check --locked -p rcs956-core --lib --target x86_64-unknown-none
    if ($LASTEXITCODE -ne 0) { throw 'Core no_std check failed' }
    cargo test --locked --workspace
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    cargo clippy --locked --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed' }
    $env:RUSTDOCFLAGS = '-D warnings'
    cargo doc --locked --workspace --no-deps
    if ($LASTEXITCODE -ne 0) { throw 'Rustdoc failed' }
} finally {
    $env:RUSTDOCFLAGS = $savedRustdocFlags
    Pop-Location
}
