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

use futures::executor::block_on;

/// Simple async tcp connect scanner
pub fn main() {
    let addresses = std::env::args().nth(1).expect("No addresses given");
    let ports = std::env::args().nth(2).expect("No ports given");

    let scanner = QScanner::new(&addresses, &ports, 1000, 1000, 1);
    let res = block_on(scanner.scan_tcp_connect());

    for sa in &res {
        println!("{}", sa);
    }
}
