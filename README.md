# Quick Network Scanner

Rust library for scanning network hosts asynchronously.

Currently only TCP connect scan is supported.

NOTE: you may need to increase the maximum allowed open files. E.g.:

```bash
ulimit -n 10000
```

See the library on [crates.io](https://crates.io/crates/qscan).

## Usage

Dependencies (`Cargo.toml`):

```bash
[dependencies]
qscan = "0.3.0"
tokio = { version = "1", features = ["rt-multi-thread"] }
```

and then (`src/main.rs`):

```rust
use qscan::QScanner;
use tokio::runtime::Runtime;

pub fn main() {
  let scanner = QScanner::new(
                  "8.8.8.8,127.0.0.1",
                  "0-1024",
                  5000, 2000, 1);
  let res = Runtime::new()
      .unwrap() .block_on(scanner.scan_tcp_connect(false));

  for sa in &res {
      println!("{}", sa);
  }
}
```

## tcp_cs

The project provides a simple scanner binary called `tcp_cs` that can be build
and used as follow:

```bash
cargo build --release --features build-binary --bin tcp_cs
./target/release/tcp_cs --ips "8.8.8.8" --ports "1-1000"
```

See the help message for all the available options:

```bash
./target/debug/tcp_cs -h
qscan 0.3.0
0xor0ne
Quick async network scan library

USAGE:
    tcp_cs [OPTIONS] --ips <IPS> --ports <PORTS>

OPTIONS:
        --batch <BATCH>        Parallel scan [default: 5000]
    -h, --help                 Print help information
        --ips <IPS>            IP to scan. E.g., '8.8.8.8', '192.168.1.0/24'
        --nortprint            Do not print open ports as soon as they are found
        --ports <PORTS>        Ports to scan for each ip. E.g., '80', '1-1024'
        --timeout <TIMEOUT>    Timeout in ms [default: 1000]
        --tries <TRIES>        #re-tries [default: 1]
    -V, --version              Print version information
```

## Docker Image

It's possible to build and use a Docker image configured for running `tcp_cs`.

NOTE: currently only Linux has been tested for building the Docker image.

Assuming Docker is installed on your machine and configured to run without sudo
(if not, see [here][1] and [here][2]), proceed by building the image:

```bash
./scripts/docker_build.sh
```

Then you can use the `0xor0ne/qscan` Docker image for running the scanner:

```bash
docker run --rm -it 0xor0ne/qscan --ips "8.8.8.8" --ports "1-1024"
```

the same thing can be done using the helper script:

```bash
./scripts/docker_run_scan.sh --ips "8.8.8.8" --ports "1-1024"
```

### Docker Image from hub.docker.com

Alternatively, it is possible to download and run a precompiled image from
hub.docker.com:

```bash
docker run --rm 0xor0ne/qscan:latest --ips "8.8.8.8" --ports "1-1024"
```

### Build Docker Image on MacOS (Experimental)

```bash
rustup target add x86_64-unknown-linux-gnu
brew tap SergioBenitez/osxct
brew install x86_64-unknown-linux-gnu
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-unknown-linux-gnu-gcc ./scripts/docker_build.sh
```

## Related Projects

* [RustScan](https://github.com/RustScan/RustScan)

[1]: https://docs.docker.com/engine/install/
[2]: https://docs.docker.com/engine/install/linux-postinstall/
