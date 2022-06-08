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

use std::fmt;

#[cfg(feature = "serialize")]
use serde::ser::{Serialize, SerializeStruct, Serializer};
#[cfg(feature = "serialize")]
use serde_json;

use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use std::num::NonZeroU8;
use std::time::Duration;

use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use itertools::Itertools;

use cidr_utils::cidr::IpCidr;

use futures::stream::{FuturesUnordered, StreamExt};

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};

/// Scanning mode:
///
/// * `TcpConnect`: TCP connect scan;
#[derive(Debug)]
pub enum QScanType {
    TcpConnect,
    // Ping, future release
}

/// Printing mode while scanning
///
/// * `NonRealTime`: do not print during async scan
/// * `RealTime`: print as soon as the result is available
#[derive(Debug)]
pub enum QSPrintMode {
    NonRealTime,
    RealTime,
    RealTimeAll,
}

/// Asynchronous network scanner
#[derive(Debug)]
pub struct QScanner {
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    scan_type: QScanType,
    print_mode: QSPrintMode,
    batch: u16,
    to: Duration,
    tries: NonZeroU8,
    last_results: Option<Vec<QScanTcpConnectResult>>,
}

/// Possible states of a TCP connect target
#[derive(Debug, PartialEq)]
pub enum QScanTcpConnectState {
    Open,
    Close,
}

/// Result of a TCP Connect Scan for a single target
#[derive(Debug)]
pub struct QScanTcpConnectResult {
    pub target: SocketAddr,
    pub state: QScanTcpConnectState,
}

#[derive(Debug, Clone)]
struct QScanError {
    msg: String,
    sock: SocketAddr,
}

impl fmt::Display for QScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "QScanError: {}", self.msg)
    }
}

#[cfg(feature = "serialize")]
impl Serialize for QScanTcpConnectResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("QScanTcpConnectResult", 3)?;
        s.serialize_field("IP", &self.target.ip())?;
        s.serialize_field("port", &self.target.port())?;
        match self.state {
            QScanTcpConnectState::Open => {
                s.serialize_field("state", "OPEN")?;
            }
            QScanTcpConnectState::Close => {
                s.serialize_field("state", "CLOSED")?;
            }
        }
        s.end()
    }
}

/// Defaults
const SCAN_TYPE: QScanType = QScanType::TcpConnect;
const PRINT_MODE: QSPrintMode = QSPrintMode::NonRealTime;
const BATCH_DEF: u16 = 2500;
const TIMEOUT_DEF: u64 = 1000;
const TRIES_DEF: u8 = 1;

impl QScanner {
    /// Create a new QScanner
    ///
    /// # Arguments
    ///
    /// * `addresses` - IPs string, comma separated and CIDR notation
    /// * `ports` - ports string, comma separated and ranges
    ///
    /// # Examples
    ///
    /// ```
    /// use qscan::qscanner::QScanner;
    /// let scanner1 = QScanner::new("127.0.0.1", "80");
    /// let scanner2 = QScanner::new("127.0.0.1,127.0.1.0/24", "80,443,1024-2048");
    /// ```
    ///
    pub fn new(addresses: &str, ports: &str) -> Self {
        Self {
            ips: addresses_parse(addresses),
            ports: ports_parse(ports),
            scan_type: SCAN_TYPE,
            print_mode: PRINT_MODE,
            batch: BATCH_DEF,
            to: Duration::from_millis(TIMEOUT_DEF),
            tries: NonZeroU8::new(std::cmp::max(TRIES_DEF, 1)).unwrap(),
            last_results: None,
        }
    }

    /// Set the scanner type
    pub fn set_scan_type(&mut self, scan_type: QScanType) {
        self.scan_type = scan_type;
    }

    /// Set the results printing mode
    pub fn set_print_mode(&mut self, print_mode: QSPrintMode) {
        self.print_mode = print_mode;
    }

    /// Set the number of parallel scans
    pub fn set_batch(&mut self, batch: u16) {
        self.batch = batch;
    }

    /// Set the scan timeout for each target
    pub fn set_timeout_ms(&mut self, to_ms: u64) {
        self.to = Duration::from_millis(to_ms);
    }

    /// Set how many retries for each target
    /// If `ntries` is 0, it is converted to 1
    pub fn set_ntries(&mut self, ntries: u8) {
        self.tries = NonZeroU8::new(std::cmp::max(ntries, 1)).unwrap();
    }

    pub fn get_last_results(&self) -> Option<&Vec<QScanTcpConnectResult>> {
        match &self.last_results {
            Some(res) => Some(res),
            None => None,
        }
    }

    /// QScanner caches the results of the latest scan. This function clear the cache.
    pub fn reset_last_results(&mut self) {
        if let Some(last_res) = &mut self.last_results {
            last_res.clear();
            self.last_results = None;
        }
    }

    /// Return the vector of target IP addresses
    pub fn get_tagets_ips(&self) -> &Vec<IpAddr> {
        &self.ips
    }

    /// Return the vector of target ports
    pub fn get_tagets_ports(&self) -> &Vec<u16> {
        &self.ports
    }

    /// Set targets. Old targets are discarded
    ///
    /// # Arguments
    ///
    /// * `addresses` - IPs string, comma separated and CIDR notation
    /// * `ports` - ports string, comma separated and ranges
    ///
    pub fn set_targets(&mut self, addresses: &str, ports: &str) {
        self.ips = addresses_parse(addresses);
        self.ports = ports_parse(ports);
    }

    /// Add targets to existing targets
    ///
    /// # Arguments
    ///
    /// * `addresses` - IPs string, comma separated and CIDR notation
    /// * `ports` - ports string, comma separated and ranges
    ///
    pub fn add_targets(&mut self, addresses: &str, ports: &str) {
        self.ips.extend(addresses_parse(addresses));
        self.ips = self
            .ips
            .clone()
            .into_iter()
            .unique()
            .collect::<Vec<IpAddr>>();
        self.ports.extend(ports_parse(ports));
        self.ports = self
            .ports
            .clone()
            .into_iter()
            .unique()
            .collect::<Vec<u16>>();
    }

    /// Set targets. Old targets are discarded
    ///
    /// # Arguments
    ///
    /// * `ips` - Target IPs
    /// * `ports` - Target ports
    ///
    /// # Examples
    ///
    ///```
    /// use qscan::qscanner::QScanner;
    /// use std::net::{IpAddr, Ipv4Addr};
    /// let mut qs = QScanner::new("", "");
    /// let target_ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
    /// let target_ports = vec![80];
    /// qs.set_vec_targets(target_ips, target_ports);
    /// ```
    pub fn set_vec_targets(&mut self, ips: Vec<IpAddr>, ports: Vec<u16>) {
        self.ips = ips;
        self.ports = ports;
    }

    /// Set targets. Old targets are discarded
    ///
    /// # Arguments
    ///
    /// * `ips` - Target IPs
    /// * `ports` - Target ports
    ///
    /// # Examples
    ///
    /// ```
    /// use qscan::qscanner::QScanner;
    /// use std::net::{IpAddr, Ipv4Addr};
    /// let mut qs = QScanner::new("127.0.0.1", "80");
    /// let target_ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))];
    /// let target_ports = vec![443];
    /// qs.add_vec_targets(target_ips, target_ports);
    /// ```
    pub fn add_vec_targets(&mut self, ips: Vec<IpAddr>, ports: Vec<u16>) {
        self.ips.extend(ips);
        self.ips = self
            .ips
            .clone()
            .into_iter()
            .unique()
            .collect::<Vec<IpAddr>>();
        self.ports.extend(ports);
        self.ports = self
            .ports
            .clone()
            .into_iter()
            .unique()
            .collect::<Vec<u16>>();
    }

    #[cfg(feature = "serialize")]
    pub fn get_last_results_as_json_string(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self.last_results)
    }

    /// Async TCP connect scan
    ///
    /// # Return
    ///
    /// A vector of [SocketAddr] for each open port found.
    ///
    /// # Examples
    ///
    /// ```
    /// use qscan::qscanner::QScanner;
    /// use tokio::runtime::Runtime;
    /// let scanner = QScanner::new("127.0.0.1", "80");
    /// let res = Runtime::new().unwrap().block_on(scanner.scan_tcp_connect());
    /// ```
    ///
    pub async fn scan_tcp_connect(&mut self) -> &Vec<QScanTcpConnectResult> {
        let mut sock_res: Vec<QScanTcpConnectResult> = Vec::new();
        let mut sock_it: sockiter::SockIter = sockiter::SockIter::new(&self.ips, &self.ports);
        let mut ftrs = FuturesUnordered::new();

        for _ in 0..self.batch {
            if let Some(socket) = sock_it.next() {
                ftrs.push(self.scan_socket_tcp_connect(socket));
            } else {
                break;
            }
        }

        while let Some(result) = ftrs.next().await {
            if let Some(socket) = sock_it.next() {
                ftrs.push(self.scan_socket_tcp_connect(socket));
            }

            match result {
                Ok(socket) => {
                    match self.print_mode {
                        QSPrintMode::RealTime => {
                            println!("{}:{}", socket.ip(), socket.port());
                        }
                        QSPrintMode::RealTimeAll => {
                            println!("{}:{}:OPEN", socket.ip(), socket.port());
                        }
                        _ => {}
                    }

                    sock_res.push(QScanTcpConnectResult {
                        target: socket,
                        state: QScanTcpConnectState::Open,
                    });
                }
                Err(error) => {
                    if let QSPrintMode::RealTimeAll = self.print_mode {
                        println!("{}:{}:CLOSED", error.sock.ip(), error.sock.port());
                    }

                    sock_res.push(QScanTcpConnectResult {
                        target: error.sock,
                        state: QScanTcpConnectState::Close,
                    });
                }
            }
        }

        drop(ftrs);
        self.last_results = Some(sock_res);
        self.last_results.as_ref().unwrap()
    }

    async fn scan_socket_tcp_connect(&self, socket: SocketAddr) -> Result<SocketAddr, QScanError> {
        let tries = self.tries.get();

        for ntry in 0..tries {
            match self.tcp_connect(socket).await {
                Ok(Ok(mut x)) => {
                    if x.shutdown().await.is_err() {
                        return Err(QScanError {
                            msg: "Shutdown error".to_string(),
                            sock: socket,
                        });
                    } else {
                        return Ok(socket);
                    }
                }
                Ok(Err(e)) => {
                    let mut err_str = e.to_string();

                    if err_str.to_lowercase().contains("too many open files") {
                        panic!("Too many open files, reduce batch size {}", self.batch);
                    }

                    if ntry == tries - 1 {
                        err_str.push(' ');
                        err_str.push_str(&socket.ip().to_string());
                        return Err(QScanError {
                            msg: err_str,
                            sock: socket,
                        });
                    }
                }
                Err(e) => {
                    let mut err_str = e.to_string();

                    if ntry == tries - 1 {
                        err_str.push(' ');
                        err_str.push_str(&socket.ip().to_string());
                        return Err(QScanError {
                            msg: err_str,
                            sock: socket,
                        });
                    }
                }
            };
        }
        unreachable!();
    }

    async fn tcp_connect(&self, socket: SocketAddr) -> Result<io::Result<TcpStream>, Elapsed> {
        // See https://stackoverflow.com/questions/30022084/how-do-i-set-connect-timeout-on-tcpstream
        timeout(self.to, TcpStream::connect(socket)).await
    }
}

/// Parse ports strings, comma separated strings and ranges.
/// E.g., "80", "80,443", "80,100-200,443"
fn ports_parse(ports: &str) -> Vec<u16> {
    let mut pv: Vec<u16> = Vec::new();
    let ps: String = ports.chars().filter(|c| !c.is_whitespace()).collect();

    for p in ps.split(',') {
        if p.is_empty() {
            continue;
        }

        let range = p
            .split('-')
            .map(str::parse)
            .collect::<Result<Vec<u16>, std::num::ParseIntError>>()
            .unwrap();

        match range.len() {
            1 => pv.push(range[0]),
            2 => pv.extend(range[0]..=range[1]),
            _ => {
                panic!("Invalid Range: {:?}", range);
            }
        }
    }

    pv.into_iter().unique().collect::<Vec<u16>>()
}

/// Parse IP addresses strings.
/// E.g., "1.2.3.4", "1.2.3.4,8.8.8.8", 192.168.1.0/24"
fn addresses_parse(addresses: &str) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let alt_resolver =
        Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();

    let addrs: String = addresses.chars().filter(|c| !c.is_whitespace()).collect();

    for addr in addrs.split(',') {
        if addr.is_empty() {
            continue;
        }

        let parsed_addr = address_parse(addr, &alt_resolver);

        if !parsed_addr.is_empty() {
            ips.extend(parsed_addr);
        } else {
            // Check if we have a file to read addresses from
            let file_path = Path::new(addr);
            if !file_path.is_file() {
                println!("Error: not a file {:?}", addr);
                continue;
            }

            if let Ok(x) = read_addresses_from_file(file_path, &alt_resolver) {
                ips.extend(x);
            } else {
                println!("Error: unknown target {:?}", addr);
            }
        }
    }

    ips.into_iter().unique().collect::<Vec<IpAddr>>()
}

fn address_parse(addr: &str, resolver: &Resolver) -> Vec<IpAddr> {
    IpCidr::from_str(&addr)
        .map(|cidr| cidr.iter().collect())
        .ok()
        .or_else(|| {
            format!("{}:{}", &addr, 80)
                .to_socket_addrs()
                .ok()
                .map(|mut iter| vec![iter.next().unwrap().ip()])
        })
        .unwrap_or_else(|| domain_name_resolve_to_ip(addr, resolver))
}

fn domain_name_resolve_to_ip(source: &str, alt_resolver: &Resolver) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();

    if let Ok(addrs) = source.to_socket_addrs() {
        for ip in addrs {
            ips.push(ip.ip());
        }
    } else if let Ok(addrs) = alt_resolver.lookup_ip(source) {
        ips.extend(addrs.iter());
    }

    ips
}

// Read ips or fomain name from a file
fn read_addresses_from_file(
    addrs_file_path: &Path,
    backup_resolver: &Resolver,
) -> Result<Vec<IpAddr>, std::io::Error> {
    let file = File::open(addrs_file_path)?;
    let reader = BufReader::new(file);
    let mut ips: Vec<IpAddr> = Vec::new();

    for (idx, address_line) in reader.lines().enumerate() {
        if let Ok(address) = address_line {
            ips.extend(address_parse(&address, backup_resolver));
        } else {
            println!("Error: Line {} in file is not valid", idx);
        }
    }

    Ok(ips)
}

mod sockiter {
    use itertools::{iproduct, Product};
    use std::net::{IpAddr, SocketAddr};

    pub struct SockIter<'a> {
        prod: Product<Box<std::slice::Iter<'a, u16>>, Box<std::slice::Iter<'a, std::net::IpAddr>>>,
    }

    impl<'a> SockIter<'a> {
        pub fn new(ips: &'a [IpAddr], ports: &'a [u16]) -> Self {
            let ports = Box::new(ports.iter());
            let ips = Box::new(ips.iter());
            Self {
                prod: iproduct!(ports, ips),
            }
        }
    }

    impl<'s> Iterator for SockIter<'s> {
        type Item = SocketAddr;

        fn next(&mut self) -> Option<Self::Item> {
            self.prod
                .next()
                .map(|(port, ip)| SocketAddr::new(*ip, *port))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        Resolver,
    };

    use tokio::runtime::Runtime;

    #[test]
    fn parse_empty_address() {
        let res = super::addresses_parse("");
        assert_eq!(res, Vec::<IpAddr>::new());
    }

    #[test]
    fn parse_commas_address() {
        let res = super::addresses_parse(",,,,");
        assert_eq!(res, Vec::<IpAddr>::new());
    }

    #[test]
    fn parse_simple_address() {
        let res = super::addresses_parse("127.0.0.1");
        assert_eq!(res, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_repeated_address1() {
        let res = super::addresses_parse("127.0.0.1,127.0.0.1");
        assert_eq!(res, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_repeated_address2() {
        let res = super::addresses_parse("127.0.0.1,127.0.0.2,127.0.0.0/30");
        assert_eq!(
            res,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
                "127.0.0.0".parse::<IpAddr>().unwrap(),
                "127.0.0.3".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_repeated_address3() {
        let res = super::addresses_parse("127.0.0.1,192.168.1.1,127.0.0.0/30");
        assert_eq!(
            res,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "127.0.0.0".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
                "127.0.0.3".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_multiple_addresses() {
        let res = super::addresses_parse("127.0.0.1,127.0.0.2");
        assert_eq!(
            res,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_cidr() {
        let res = super::addresses_parse("127.0.0.10/31");
        assert_eq!(
            res,
            vec![
                "127.0.0.10".parse::<IpAddr>().unwrap(),
                "127.0.0.11".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_cidr_and_addresses() {
        let res = super::addresses_parse("127.0.0.1,127.0.0.10/31, 127.0.0.2");
        assert_eq!(
            res,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.10".parse::<IpAddr>().unwrap(),
                "127.0.0.11".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_empty_port() {
        let res = super::ports_parse("");
        assert_eq!(res, Vec::new());
    }

    #[test]
    fn parse_commas_port() {
        let res = super::ports_parse(",,,");
        assert_eq!(res, Vec::new());
    }

    #[test]
    fn parse_single_port() {
        let res = super::ports_parse("80");
        assert_eq!(res, vec![80]);
    }

    #[test]
    fn parse_repeated_port1() {
        let res = super::ports_parse("80,80");
        assert_eq!(res, vec![80]);
    }

    #[test]
    fn parse_repeated_port2() {
        let res = super::ports_parse("80,79-81");
        assert_eq!(res, vec![80, 79, 81]);
    }

    #[test]
    fn parse_repeated_port3() {
        let res = super::ports_parse("80,128,79-81");
        assert_eq!(res, vec![80, 128, 79, 81]);
    }

    #[test]
    fn parse_multiple_ports() {
        let res = super::ports_parse("80, 443,8080");
        assert_eq!(res, vec![80, 443, 8080]);
    }

    #[test]
    fn parse_ports_range() {
        let res = super::ports_parse("80-83");
        assert_eq!(res, vec![80, 81, 82, 83]);
    }

    #[test]
    fn parse_ports_mixed() {
        let res = super::ports_parse("21,80-83,443,8080-8081");
        assert_eq!(res, vec![21, 80, 81, 82, 83, 443, 8080, 8081]);
    }

    #[test]
    fn set_new_targets() {
        let mut scanner = super::QScanner::new("", "");
        scanner.set_targets("1.1.1.1", "80");
        assert_eq!(
            *scanner.get_tagets_ips(),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(*scanner.get_tagets_ports(), vec![80]);
    }

    #[test]
    fn add_new_targets() {
        let mut scanner = super::QScanner::new("127.0.0.1", "80");
        scanner.add_targets("127.0.0.0/30,192.168.1.1", "79-80,81");
        assert_eq!(
            *scanner.get_tagets_ips(),
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.0".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
                "127.0.0.3".parse::<IpAddr>().unwrap(),
                "192.168.1.1".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(*scanner.get_tagets_ports(), vec![80, 79, 81]);
    }

    #[test]
    fn set_vec_new_targets() {
        let mut scanner = super::QScanner::new("", "");
        let target_ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        let target_ports = vec![80];
        scanner.set_vec_targets(target_ips, target_ports);
        assert_eq!(
            *scanner.get_tagets_ips(),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(*scanner.get_tagets_ports(), vec![80]);
    }

    #[test]
    fn add_vec_new_targets() {
        let mut scanner = super::QScanner::new("127.0.0.1", "80");
        let target_ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ];
        let target_ports = vec![443, 80, 53];
        scanner.add_vec_targets(target_ips, target_ports);
        assert_eq!(
            *scanner.get_tagets_ips(),
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(*scanner.get_tagets_ports(), vec![80, 443, 53]);
    }

    #[test]
    fn scan_tcp_connect_google_dns() {
        let scanner = super::QScanner::new("8.8.8.8", "53,54,55-60");
        let res = Runtime::new().unwrap().block_on(scanner.scan_tcp_connect());

        for r in res {
            if r.state == super::QScanTcpConnectState::Open {
                assert_eq!(
                    r.target,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
                );
            }
        }
    }

    #[test]
    fn resolve_localhost() {
        let resolver =
            Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
        let res = super::domain_name_resolve_to_ip("localhost", &resolver);
        assert_eq!(res, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }

    #[test]
    fn resolve_lhost() {
        let resolver =
            Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
        let res = super::domain_name_resolve_to_ip("www.google.com", &resolver);
        assert!(res.len() > 0);
    }
}
