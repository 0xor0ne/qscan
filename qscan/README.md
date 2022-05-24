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
qscan = "0.3.3"
tokio = { version = "1", features = ["rt-multi-thread"] }
```

and then (`src/main.rs`):

```rust
use qscan::QScanner;
use tokio::runtime::Runtime;

pub fn main() {
    let scanner = QScanner::new("8.8.8.8,127.0.0.1", "53,80,443", 5000, 2000, 1);
    let res = Runtime::new()
        .unwrap()
        .block_on(scanner.scan_tcp_connect(false));

    for sa in &res {
        println!("{}", sa);
    }
}
```

See also the [provided example](./examples/scan.rs).
