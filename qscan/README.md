# Quick Network Scanner Library

Rust library for scanning network hosts asynchronously.

Currently only TCP connect scan is supported.

NOTE: in order to properly use the library you may need to increase the maximum
allowed open files. E.g.:

```bash
ulimit -n 10000
```

See the library on [crates.io](https://crates.io/crates/qscan).

## Usage

Dependencies (`Cargo.toml`):

```bash
[dependencies]
qscan = "0.4.0"
tokio = { version = "1", features = ["rt-multi-thread"] }
```

and then (`src/main.rs`):

```rust
use qscan::qscanner::{QSPrintMode, QScanTcpConnectState, QScanType, QScanner};
use tokio::runtime::Runtime;

pub fn main() {
    let mut scanner = QScanner::new("8.8.8.8,127.0.0.1", "53,80,443");
    scanner.set_batch(5000);
    scanner.set_timeout_ms(2000);
    scanner.set_ntries(1);
    scanner.set_scan_type(QScanType::TcpConnect);
    scanner.set_print_mode(QSPrintMode::NonRealTime);

    let res = Runtime::new().unwrap().block_on(scanner.scan_tcp_connect());

    for sa in &res {
        if sa.state == QScanTcpConnectState::Open {
            println!("{}", sa.target);
        }
    }
}
```

See also the [provided example](./examples/scan.rs).
