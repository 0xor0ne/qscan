# Quick Network Scanner

Rust library for scanning network hosts asynchronously.

Currently only TCP connect scan is supported.

## Usage

```rust
use qscan::QScanner;
use futures::executor::block_on;

pub fn main() {
  let scanner = QScanner::new(
                  "127.0.0.0/24,8.8.8.8",
                  "53,443,8000-9000",
                  1000, 1000, 1);
  let res = block_on(scanner.scan_tcp_connect());
}
```

## tcp_cs

The project provides a simple scanner binary called `tcp_cs` that can be build
and used as follow:

```bash
cargo build --release
./target/release/tcp_cs "8.8.8.8" "1-1000"
```

NOTE: you may need to increase the maximum allowed open files. E.g.,:

```bash
ulimit -n 10000
```

## Docker Image

It's possible to build and use a Docker image configured for running `tcp_cs`.

Assuming Docker is installed on your machine and configured to run without sudo
(if not, see [here][1] and [here][2]), proceed
by building the image:

```bash
./scripts/docker_build.sh
```

Then you can use the `qscan` Docker image for running the scanner:

```bash
./scripts/docker_run_scan.sh "8.8.8.8" "53"
```

### Docker Image from hub.docker.com

Alternatively, it is possible to download and run a precompiled image from
hub.docker.com:

```bash
docker run --rm 0xor0ne/qscan:latest "8.8.8.8" "80
```

## Related Projects

* [RustScan](https://github.com/RustScan/RustScan)

[1]: https://docs.docker.com/engine/install/
[2]: https://docs.docker.com/engine/install/linux-postinstall/
