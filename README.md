# Quick Network Scanner Library

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
qscan = "0.3.2"
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

The project provides a simple scanner utility called `tcp_cs` that can be build
and used as follow:

```bash
cargo build --release --features build-binary --bin tcp_cs
```

See the help message for all the available options:

```bash
./target/debug/tcp_cs -h
qscan 0.3.2
0xor0ne
Quick async network scan library

USAGE:
    tcp_cs [OPTIONS] --targets <TARGETS> --ports <PORTS>

OPTIONS:
        --batch <BATCH>        Parallel scan [default: 5000]
    -h, --help                 Print help information
        --nortprint            Print open ports at the end of the scan and not as soon as they are
                               found
        --ports <PORTS>        Comma separate list of ports (or port ranges) to scan for each
                               target. E.g., '80', '22,443', '1-1024,8080'
        --targets <TARGETS>    Comma separated list of targets to scan. A target can be an IP, a set
                               of IPs in CIDR notation, a domain name or a path to a file containing
                               one of the previous for each line. E.g., '8.8.8.8', '192.168.1.0/24',
                               'www.google.com,/tmp/ips.txt'
        --timeout <TIMEOUT>    Timeout in ms. If the timeout expires the port is considered close
                               [default: 1500]
        --tries <TRIES>        Number of maximum retries for each target:port pair [default: 1]
    -V, --version              Print version information
```

And here are a few usage examples:

```bash
# Single target, multiple port
./target/release/tcp_cs --targets "8.8.8.8" --ports "1-1000"
# Scan local lan for SSH (assuming 192.168.1.0/24). In this case we reduce the
# timeout to 500ms.
./target/release/tcp_cs --targets "192.168.1.0/24" --ports "22" --timeout 500
# Use a domain name as target
./target/release/tcp_cs --targets "www.google.com" --ports "80,443"
# Use a file as target, the file must contain a target (IP, cidr or domain name)
# for each line
./target/release/tcp_cs --targets "/tmp/ips.txt" --ports "1-1024"
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
docker run --rm -it 0xor0ne/qscan --targets "8.8.8.8" --ports "1-1024"
```

the same thing can be done using the helper script:

```bash
./scripts/docker_run_scan.sh --targets "8.8.8.8" --ports "1-1024"
```

### Docker Image from hub.docker.com

Alternatively, it is possible to download and run a precompiled image from
hub.docker.com:

```bash
docker run --rm 0xor0ne/qscan:latest --targets "8.8.8.8" --ports "1-1024"
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
