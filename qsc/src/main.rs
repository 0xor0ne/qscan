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

//! # QSC
//!
//! Quick async network scanner CLI
//!
//! ## USAGE:
//!
//!   `qsc [OPTIONS] --targets <TARGETS> --ports <PORTS>`
//!
//! ## OPTIONS:
//!
//! ```text
//!        --batch <BATCH>
//!            Parallel scan [default: 5000]
//!
//!    -h, --help
//!            Print help information
//!
//!        --json <JSON>
//!            Path to file whre to save results in json format
//!
//!        --mode <MODE>
//!            Scan mode:
//!              - 0: TCP connect;
//!              - 1: ping (--ports is ognored);
//!              - 2: ping and then TCP connect using as targets the nodes that replied to the ping;
//!                     [default: 0]
//!
//!        --ping-interval <PING_INTERVAL>
//!            Inteval in ms between pings for a single target. [default: 1000]
//!
//!        --ping-tries <PING_TRIES>
//!            Number of maximum retries for each target (ping scan) [default: 1]
//!
//!        --ports <PORTS>
//!            Comma separate list of ports (or port ranges) to scan for each target. E.g., '80',
//!            '22,443', '1-1024,8080'
//!
//!        --printlevel <PRINTLEVEL>
//!            Console output mode:
//!              - 0: suppress console output;
//!              - 1: print ip:port for open ports at the end of the scan;
//!              - 2: print ip:port:<OPEN|CLOSE> at the end of the scan;
//!              - 3: print ip:port for open ports as soon as they are found;
//!              - 4: print ip:port:<OPEN:CLOSE> as soon as the scan for a
//!                   target ends;
//!                     [default: 3]
//!
//!        --targets <TARGETS>
//!            Comma separated list of targets to scan. A target can be an IP, a set of IPs in CIDR
//!            notation, a domain name or a path to a file containing one of the previous for each
//!            line. E.g., '8.8.8.8', '192.168.1.0/24', 'www.google.com,/tmp/ips.txt'
//!
//!        --tcp-tries <TCP_TRIES>
//!            Number of maximum retries for each target:port pair (TCP Connect scan) [default: 1]
//!
//!        --timeout <TIMEOUT>
//!            Timeout in ms. If the timeout expires the port is considered close [default: 1500]
//!
//!    -V, --version
//!            Print version information
//!
//! ```

use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;

use qscan::{QSPrintMode, QScanPingState, QScanResult, QScanTcpConnectState, QScanType, QScanner};

use clap::Parser;
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[doc(hidden)]
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
        default_value_t = 1000,
        help = "Inteval in ms between pings for a single target."
    )]
    ping_interval: u64,

    #[clap(
        long,
        default_value_t = 1,
        help = "Number of maximum retries for each target:port pair (TCP Connect scan)"
    )]
    tcp_tries: u8,

    #[clap(
        long,
        default_value_t = 1,
        help = "Number of maximum retries for each target (ping scan)"
    )]
    ping_tries: u8,

    #[clap(
        long,
        default_value_t = 3,
        help = "Console output mode:
  - 0: suppress console output;
  - 1: print ip:port for open ports at the end of the scan;
  - 2: print ip:port:<OPEN|CLOSE> at the end of the scan;
  - 3: print ip:port for open ports as soon as they are found;
  - 4: print ip:port:<OPEN:CLOSE> as soon as the scan for a
       target ends;
        "
    )]
    printlevel: u8,

    #[clap(
        long,
        default_value_t = 0,
        help = "Scan mode:
  - 0: TCP connect;
  - 1: ping (--ports is ognored);
  - 2: ping and then TCP connect using as targets the nodes that replied to the ping;
        "
    )]
    mode: u8,

    #[clap(long, help = "Path to file whre to save results in json format")]
    json: Option<PathBuf>,
}

#[doc(hidden)]
fn do_tcp_connect_scan_and_print(scanner: &mut QScanner, args: &Args) {
    scanner.set_scan_type(QScanType::TcpConnect);
    scanner.set_ntries(args.tcp_tries);
    set_print_level(scanner, args);
    let res: &Vec<QScanResult> = Runtime::new().unwrap().block_on(scanner.scan_tcp_connect());

    if (args.printlevel == 0) && (args.printlevel == 1 || args.printlevel == 2) {
        for r in res {
            if let QScanResult::TcpConnect(sa) = r {
                if sa.state == QScanTcpConnectState::Open {
                    if args.printlevel == 1 {
                        println!("{}", sa.target);
                    } else {
                        println!("{}:OPEN", sa.target);
                    }
                } else if args.printlevel == 2 {
                    println!("{}:CLOSED", sa.target);
                }
            }
        }
    }
}

#[doc(hidden)]
fn do_ping_scan<'a>(scanner: &'a mut QScanner, args: &Args) -> &'a Vec<QScanResult> {
    scanner.set_scan_type(QScanType::Ping);
    scanner.set_ntries(args.ping_tries);
    scanner.set_ping_interval_ms(args.ping_interval);
    Runtime::new().unwrap().block_on(scanner.scan_ping())
}

#[doc(hidden)]
fn do_ping_scan_and_print(scanner: &mut QScanner, args: &Args) {
    set_print_level(scanner, args);
    let res: &Vec<QScanResult> = do_ping_scan(scanner, args);

    if (args.printlevel == 0) && (args.printlevel == 1 || args.printlevel == 2) {
        for r in res {
            if let QScanResult::Ping(pr) = r {
                if pr.state == QScanPingState::Up {
                    if args.printlevel == 1 {
                        println!("{}", pr.target);
                    } else {
                        println!("{}:UP", pr.target);
                    }
                } else if args.printlevel == 2 {
                    println!("{}:DOWN", pr.target);
                }
            }
        }
    }
}

#[doc(hidden)]
fn set_print_level(scanner: &mut QScanner, args: &Args) {
    match args.printlevel {
        1 | 2 => scanner.set_print_mode(QSPrintMode::NonRealTime),
        3 => scanner.set_print_mode(QSPrintMode::RealTime),
        4 => scanner.set_print_mode(QSPrintMode::RealTimeAll),
        _ => {
            panic!("Unknown print mode {} (allowed 0-4)", args.printlevel);
        }
    }
}

/// Simple async tcp connect scanner
#[doc(hidden)]
fn main() {
    let args = Args::parse();
    let batch = args.batch;
    let timeout = args.timeout;
    let mut jf: Option<File> = None;

    if args.json.is_some() {
        jf = if let Ok(f) = File::create(&args.json.as_ref().unwrap().as_path()) {
            Some(f)
        } else {
            panic!(
                "Cannot create file {}",
                args.json.unwrap().to_str().unwrap()
            );
        }
    }

    let mut scanner = QScanner::new(&args.targets, &args.ports);

    scanner.set_batch(batch);
    scanner.set_timeout_ms(timeout);

    match args.mode {
        0 => do_tcp_connect_scan_and_print(&mut scanner, &args),
        1 => do_ping_scan_and_print(&mut scanner, &args),
        2 => {
            scanner.set_print_mode(QSPrintMode::NonRealTime);
            let res: &Vec<QScanResult> = do_ping_scan(&mut scanner, &args);

            let mut ips_up: Vec<IpAddr> = Vec::new();

            for r in res {
                if let QScanResult::Ping(pr) = r {
                    if let QScanPingState::Up = pr.state {
                        ips_up.push(pr.target);
                    }
                }
            }

            scanner.set_vec_targets_addr(ips_up);
            do_tcp_connect_scan_and_print(&mut scanner, &args);
        }
        _ => panic!("Unknown scan mode {}", args.mode),
    }

    if let Some(mut f) = jf {
        let j = scanner.get_last_results_as_json_string().unwrap();
        if let Err(e) = f.write_all(j.as_bytes()) {
            eprintln!(
                "Error writing json results in {}: {}",
                args.json.unwrap().to_str().unwrap(),
                e
            );
        }
    }
}
