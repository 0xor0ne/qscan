# Quick Network Scanner CLI

Rust command line utility for quick asynchronous network hosts scanning.

> NOTE: in order to use the tool you may need to increase the maximum allowed
> open files. E.g.:

```bash
ulimit -n 10000
```

> NOTE: for the ping scan mode, you need `root` or other
> proper permissions (i.e. CAP_NET_RAW).

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
qsc 0.4.0
0xor0ne
Quick async network scanner CLI

USAGE:
    qsc [OPTIONS] --targets <TARGETS> --ports <PORTS>

OPTIONS:
        --batch <BATCH>
            Parallel scan [default: 5000]

    -h, --help
            Print help information

        --json <JSON>
            Path to file whre to save results in json format

        --mode <MODE>
            Scan mode:
              - 0: TCP connect;
              - 1: ping (--ports is ognored);
              - 2: ping and then TCP connect using as targets the nodes that replied to the ping;
                     [default: 0]

        --ping-interval <PING_INTERVAL>
            Inteval in ms between pings for a single target. [default: 1000]

        --ping-tries <PING_TRIES>
            Number of maximum retries for each target (ping scan) [default: 1]

        --ports <PORTS>
            Comma separate list of ports (or port ranges) to scan for each target. E.g., '80',
            '22,443', '1-1024,8080'

        --printlevel <PRINTLEVEL>
            Console output mode:
              - 0: suppress console output;
              - 1: print ip:port for open ports at the end of the scan;
              - 2: print ip:port:<OPEN|CLOSE> at the end of the scan;
              - 3: print ip:port for open ports as soon as they are found;
              - 4: print ip:port:<OPEN:CLOSE> as soon as the scan for a
                   target ends;
                     [default: 3]

        --targets <TARGETS>
            Comma separated list of targets to scan. A target can be an IP, a set of IPs in CIDR
            notation, a domain name or a path to a file containing one of the previous for each
            line. E.g., '8.8.8.8', '192.168.1.0/24', 'www.google.com,/tmp/ips.txt'

        --tcp-tries <TCP_TRIES>
            Number of maximum retries for each target:port pair (TCP Connect scan) [default: 1]

        --timeout <TIMEOUT>
            Timeout in ms. If the timeout expires the port is considered close [default: 1500]

    -V, --version
            Print version information
```

here are a few usage examples:

```bash
# Single target, multiple ports
qsc --targets "8.8.8.8" --ports "1-1000"

# Scan local lan (assuming 192.168.1.0/24) for SSH default port. In this case we
# are reducing the timeout to 500ms.
qsc --targets "192.168.1.0/24" --ports "22" --timeout 500

# Use a domain name as target
qsc --targets "www.google.com" --ports "80,443"

# Use a file as target, the file must contain a target (IP, cidr or domain name)
# for each line
qsc --targets "/tmp/ips.txt" --ports "1-1024"

# Print all the ports with OPEN/CLOSE indication and save results in json
# format in file /tmp/res.json
qsc --targets "8.8.8.8" --ports 80,443,111 --tcp-tries 1 --json /tmp/xxx.json --printlevel 4

# Ping scan: 3 re-tries, 1s timeout, 1s interval between pings. Print UP/DOWN info
sudo qsc --targets "8.8.8.8,1.2.3.4" --ports "" --mode 1 --ping-tries 3 --timeout 1000 --ping-interval 1000 --printlevel 4

# Ping+TCP connect scan (assuming 192.168.1.0/24 is your local network)
# Scan ports 22, 80 and 443 for all targets that answer to ping
# Also, save results in json format in /tmp/res.json
sudo qsc --targets "192.168.1.0/24" --ports "22,80,443" --mode 2 --ping-tries 1 --timeout 1000 --ping-interval 1000 --printlevel 4 --json /tmp/res.json
```

## Docker Image

It's possible to build and use a Docker image configured for running `qsc`.

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
