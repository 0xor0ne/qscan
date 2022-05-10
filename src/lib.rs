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

use std::net::IpAddr;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use std::num::NonZeroU8;
use std::time::Duration;

use async_std::io;
use async_std::net::TcpStream;

use cidr_utils::cidr::IpCidr;

use futures::stream::{FuturesUnordered, StreamExt};

/// Simple async network scanner
#[derive(Debug)]
pub struct QScanner {
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    batch: u16,
    to: Duration,
    tries: NonZeroU8,
}

impl QScanner {
    /// Create a new QScanner
    ///
    /// # Arguments
    ///
    /// * `addresses` - IPs string, comma separated and CIDR notation
    /// * `ports` - ports string, comma separated and ranges
    /// * `batch` - concurrent scans
    /// * `to_ms` - timeout in milliseconds
    /// * `tries` - retries for each pair of ip:port
    ///
    /// # Examples
    ///
    /// ```
    /// use qscan::QScanner;
    /// let scanner1 = QScanner::new("127.0.0.1", "80", 1000, 1000, 1);
    /// let scanner2 = QScanner::new("127.0.0.1,127.0.1.0/24", "80,443,1024-2048", 1000, 1000, 1);
    /// ```
    ///
    pub fn new(addresses: &str, ports: &str, batch: u16, to_ms: u64, tries: u8) -> Self {
        Self {
            ips: Self::addresses_parse(addresses),
            ports: Self::ports_parse(ports),
            batch,
            to: Duration::from_millis(to_ms),
            tries: NonZeroU8::new(std::cmp::max(tries, 1)).unwrap(),
        }
    }

    /// Parse ports strings, comma separated strings and ranges.
    /// E.g., "80", "80,443", "80,100-200,443"
    fn ports_parse(ports: &str) -> Vec<u16> {
        let mut pv: Vec<u16> = Vec::new();
        let ps: String = ports.chars().filter(|c| !c.is_whitespace()).collect();

        for p in ps.split(",") {
            let range = p
                .split('-')
                .map(str::parse)
                .collect::<Result<Vec<u16>, std::num::ParseIntError>>()
                .unwrap();

            match range.len() {
                1 => pv.push(range[0]),
                2 => pv.extend(range[0]..=range[1]),
                _ => {
                    panic!("Invalid Range: {}", format!("{:?}", range));
                }
            }
        }

        pv
    }

    /// Parse IP addresses strings.
    /// E.g., "1.2.3.4", "1.2.3.4,8.8.8.8", 192.168.1.0/24"
    fn addresses_parse(addresses: &str) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = Vec::new();

        let addrs: String = addresses.chars().filter(|c| !c.is_whitespace()).collect();

        for addr in addrs.split(",") {
            let parsed_addr = Self::address_parse(addr);

            if !parsed_addr.is_empty() {
                ips.extend(parsed_addr);
            }
        }

        ips
    }

    fn address_parse(addr: &str) -> Vec<IpAddr> {
        IpCidr::from_str(&addr)
            .map(|cidr| cidr.iter().collect())
            .ok()
            .or_else(|| {
                format!("{}:{}", &addr, 80)
                    .to_socket_addrs()
                    .ok()
                    .map(|mut iter| vec![iter.next().unwrap().ip()])
            })
            .unwrap()
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
    /// use qscan::QScanner;
    /// use futures::executor::block_on;
    /// let scanner1 = QScanner::new("127.0.0.1", "80", 1000, 1000, 1);
    /// let res = block_on(scanner1.scan_tcp_connect());
    /// ```
    ///
    pub async fn scan_tcp_connect(&self) -> Vec<SocketAddr> {
        let mut open_soc: Vec<SocketAddr> = Vec::new();
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

            if let Ok(socket) = result {
                open_soc.push(socket);
            }
        }

        open_soc
    }

    async fn scan_socket_tcp_connect(&self, socket: SocketAddr) -> io::Result<SocketAddr> {
        let tries = self.tries.get();

        for ntry in 0..tries {
            match self.tcp_connect(socket).await {
                Ok(x) => {
                    if let Err(e) = x.shutdown(Shutdown::Both) {
                        eprintln!("Shutdown error {}", &e);
                    }

                    //println!("Open {}", socket.to_string());

                    return Ok(socket);
                }
                Err(e) => {
                    let mut err_str = e.to_string();

                    if err_str.to_lowercase().contains("too many open files") {
                        panic!("Too many open files, reduce batch size {}", self.batch);
                    }

                    if ntry == tries - 1 {
                        err_str.push(' ');
                        err_str.push_str(&socket.ip().to_string());
                        return Err(io::Error::new(io::ErrorKind::Other, err_str));
                    }
                }
            };
        }
        unreachable!();
    }

    async fn tcp_connect(&self, socker: SocketAddr) -> io::Result<TcpStream> {
        let stream = io::timeout(self.to, async move { TcpStream::connect(socker).await }).await?;
        Ok(stream)
    }
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
            match self.prod.next() {
                None => None,
                Some((port, ip)) => Some(SocketAddr::new(*ip, *port)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use async_std::task::block_on;

    #[test]
    fn parse_simple_address() {
        let res = super::QScanner::addresses_parse("127.0.0.1");
        assert_eq!(res, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_multiple_addresses() {
        let res = super::QScanner::addresses_parse("127.0.0.1,127.0.0.2");
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
        let res = super::QScanner::addresses_parse("127.0.0.10/31");
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
        let res = super::QScanner::addresses_parse("127.0.0.1,127.0.0.10/31, 127.0.0.2");
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
    fn parse_single_port() {
        let res = super::QScanner::ports_parse("80");
        assert_eq!(res, vec![80]);
    }

    #[test]
    fn parse_multiple_ports() {
        let res = super::QScanner::ports_parse("80, 443,8080");
        assert_eq!(res, vec![80, 443, 8080]);
    }

    #[test]
    fn parse_ports_range() {
        let res = super::QScanner::ports_parse("80-83");
        assert_eq!(res, vec![80, 81, 82, 83]);
    }

    #[test]
    fn parse_ports_mixed() {
        let res = super::QScanner::ports_parse("21,80-83,443,8080-8081");
        assert_eq!(res, vec![21, 80, 81, 82, 83, 443, 8080, 8081]);
    }

    #[test]
    fn scan_tcp_connect_google_dns() {
        let scanner = super::QScanner::new("8.8.8.8", "53,54,55-60", 5000, 2500, 1);
        let res = block_on(scanner.scan_tcp_connect());
        assert_eq!(
            res,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)]
        );
    }
}
