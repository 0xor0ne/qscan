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
use qscan::QScanner;

use clap::Parser;
use futures::executor::block_on;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, help = "IP to scan. E.g., '8.8.8.8', '192.168.1.0/24'")]
    ips: String,

    #[clap(long, help = "Ports to scan for each ip. E.g., '80', '1-1024'")]
    ports: String,

    #[clap(long, default_value_t = 2500, help = "Parallel scan")]
    batch: u16,

    #[clap(long, default_value_t = 2500, help = "Timeout in ms")]
    timeout: u64,

    #[clap(long, default_value_t = 2, help = "#re-tries")]
    tries: u8,

    #[clap(long, help = "Do not print open ports as soon as they are found")]
    nortprint: bool,
}

/// Simple async tcp connect scanner
pub fn main() {
    let args = Args::parse();
    let addresses = args.ips;
    let ports = args.ports;
    let batch = args.batch;
    let timeout = args.timeout;
    let tries = args.tries;

    let scanner = QScanner::new(&addresses, &ports, batch, timeout, tries);
    let res = block_on(scanner.scan_tcp_connect(!args.nortprint));

    if args.nortprint {
        for sa in &res {
            println!("{}", sa);
        }
    }
}
