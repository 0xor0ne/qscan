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
//
use qscan::qscanner::QScanner;
use tokio::runtime::Runtime;

pub fn main() {
    let scanner = QScanner::new("8.8.8.8,127.0.0.1", "53,80,443", 5000, 2000, 1);
    let res = Runtime::new()
        .unwrap()
        .block_on(scanner.scan_tcp_connect(false));

    for sa in &res {
        println!("{}", sa);
    }
}
