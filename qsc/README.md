# Quick Network Scanner CLI

Rust command line utility for quick asynchronous network hosts scanning.

NOTE: in order to use the tool you may need to increase the maximum allowed
open files. E.g.:

```bash
ulimit -n 10000
```

See the CLI tool on [crates.io](https://crates.io/crates/qsc).

## Obtain `qsc`

Clone the repository and build `qsc` with:

```bash
git clone https://github.com/0xor0ne/qscan
cd qscan
cargo build --release -p qsc
# Install (optional)
cargo install --path qsc
```

If not installed, `qsc` executable can be found in `./target/release/qsc`.

Alternatively, it is possible to install from [crates.io](https://crates.io/):

```bash
cargo install qsc
```

## Usage

Print the help message using `-h` option:

```bash
>>> qsc -h
qsc 0.2.0
0xor0ne
Quick async network scanner CLI

USAGE:
    qsc [OPTIONS] --targets <TARGETS> --ports <PORTS>

OPTIONS:
        --batch <BATCH>              Parallel scan [default: 5000]
    -h, --help                       Print help information
        --ports <PORTS>              Comma separate list of ports (or port ranges) to scan for each
                                     target. E.g., '80', '22,443', '1-1024,8080'
        --printlevel <PRINTLEVEL>    Console output mode:
                                       - 0: suppress console output;
                                       - 1: print ip:port for open ports at the end of the scan;
                                       - 2: print ip:port:<OPEN|CLOSE> at the end of the scan;
                                       - 3: print ip:port for open ports as soon as they are found;
                                       - 4: print ip:port:<OPEN:CLOSE> as soon as the scan for a
                                            target ends;
                                              [default: 3]
        --targets <TARGETS>          Comma separated list of targets to scan. A target can be an IP,
                                     a set of IPs in CIDR notation, a domain name or a path to a
                                     file containing one of the previous for each line. E.g.,
                                     '8.8.8.8', '192.168.1.0/24', 'www.google.com,/tmp/ips.txt'
        --timeout <TIMEOUT>          Timeout in ms. If the timeout expires the port is considered
                                     close [default: 1500]
        --tries <TRIES>              Number of maximum retries for each target:port pair [default:
                                     1]
    -V, --version                    Print version information

```

here are a few usage examples:

```bash
# Single target, multiple port
qsc --targets "8.8.8.8" --ports "1-1000"
# Scan local lan for SSH (assuming 192.168.1.0/24). In this case we reduce the
# timeout to 500ms.
qsc --targets "192.168.1.0/24" --ports "22" --timeout 500
# Use a domain name as target
qsc --targets "www.google.com" --ports "80,443"
# Use a file as target, the file must contain a target (IP, cidr or domain name)
# for each line
qsc --targets "/tmp/ips.txt" --ports "1-1024"
```

## Docker Image

It's possible to build and use a Docker image configured for running `qsc`.

NOTE: currently only Linux has been tested for building the Docker image.

Assuming Docker is installed on your machine and configured to run without sudo
(if not, see [here][1] and [here][2]), proceed by building the image:

```bash
./qsc/scripts/docker_build.sh
```

Then you can use the `0xor0ne/qscan` Docker image for running the scanner:

```bash
docker run --rm -it 0xor0ne/qscan --targets "8.8.8.8" --ports "1-1024"
```

the same thing can be done using the helper script:

```bash
./qsc/scripts/docker_run_scan.sh --targets "8.8.8.8" --ports "1-1024"
```

### Docker Image from hub.docker.com

Alternatively, it is possible to download and run a precompiled image from
hub.docker.com:

```bash
docker run --rm 0xor0ne/qscan:latest --targets "8.8.8.8" --ports "1-1024"
```

## Related Projects

* [RustScan](https://github.com/RustScan/RustScan)

[1]: https://docs.docker.com/engine/install/
[2]: https://docs.docker.com/engine/install/linux-postinstall/
