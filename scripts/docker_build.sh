#!/usr/bin/env bash

#
# qscan
# Copyright (C) 2022  0xor0ne
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

# Get script actual directory
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR=${SCRIPT_DIR}/..

DOCKFILE=${ROOT_DIR}/Dockerfile

pushd .
cd ${ROOT_DIR}
cargo clean --target-dir target/x86_64-unknown-linux-gnu
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release \
  --features build-binary \
  --bin tcp_cs \
  --target x86_64-unknown-linux-gnu
popd

docker build -f ${DOCKFILE} -t 0xor0ne/qscan \
  --build-arg user=qscan \
  --build-arg root_password=qscan-passwd \
  ${ROOT_DIR}
