# Quick Network Scanner

Quick Network Scanner project includes:

* [qscan](./qscan/): a rust library for asynchronous network ports
  scanning (see [README](./qscan/README.md)).
* [qsc](./qsc/): a command line utility built on top of qscan library
  for quick network scanning activities (see [README](./qsc/README.md)).

> NOTE: in order to properly use the library and the command line utility
> provided by this project you may need to increase the maximum allowed open
> files. E.g.:

```bash
ulimit -n 10000
```

> NOTE: also, for using the ping scan functionality, you need `root` or other
> proper permission (i.e. CAP_NET_RAW).

## [`qsc`](./qsc/) CLI Tool: Quick Scan Example

Install `qsc` with:

```bash
cargo install qsc
```

run the scanner (TCP connect scan):

```bash
qsc --targets www.google.com --ports 1-1024
```

for more details and options see [qsc README](./qsc/README.md).

## [`qscan`](./qscan/) Library

For using `qscan` library put this dependency in your `Cargo.toml`:

```bash
[dependencies]
qscan = "0.6.0"
```

for more details and examples see [qscan README](./qscan/README.md).

## Build from Source

Clone and build with:

```bash
git clone https://github.com/0xor0ne/qscan.git
cd qscan
cargo build --release
```

## Related Projects

* [RustScan](https://github.com/RustScan/RustScan)
