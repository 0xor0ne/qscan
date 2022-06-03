//
// qscan
// Copyright (C) 2022  0xor0ne
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
use qscan::qscanner::QScanner;

use clap::Parser;
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(
        long,
        help = "Comma separated list of targets to scan. \
        A target can be an IP, a set of IPs in CIDR notation, a domain name \
        or a path to a file containing one of the previous for each line. \
        E.g., '8.8.8.8', '192.168.1.0/24', 'www.google.com,/tmp/ips.txt'"
    )]
    targets: String,

    #[clap(
        long,
        help = "Comma separate list of ports (or port ranges) to scan for each target. \
           E.g., '80', '22,443', '1-1024,8080'"
    )]
    ports: String,

    #[clap(long, default_value_t = 5000, help = "Parallel scan")]
    batch: u16,

    #[clap(
        long,
        default_value_t = 1500,
        help = "Timeout in ms. If the timeout expires the port is considered close"
    )]
    timeout: u64,

    #[clap(
        long,
        default_value_t = 1,
        help = "Number of maximum retries for each target:port pair"
    )]
    tries: u8,

    #[clap(
        long,
        help = "Print open ports at the end of the scan and not as soon as they are found"
    )]
    nortprint: bool,
}

/// Simple async tcp connect scanner
pub fn main() {
    let args = Args::parse();
    let addresses = args.targets;
    let ports = args.ports;
    let batch = args.batch;
    let timeout = args.timeout;
    let tries = args.tries;

    let scanner = QScanner::new(&addresses, &ports, batch, timeout, tries);
    let res = Runtime::new()
        .unwrap()
        .block_on(scanner.scan_tcp_connect(!args.nortprint));

    if args.nortprint {
        for sa in &res {
            println!("{}", sa);
        }
    }
}
