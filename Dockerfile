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

From debian:stable-slim

LABEL description="Quick Scanner Container"

ARG user=qscan
ARG root_password=qscan-passwd

# Setup environment
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -y
RUN apt-get install -y --no-install-recommends \
      build-essential \
      sudo \
      curl \
      ca-certificates \
      locales

# Enable UTF-8 locale
RUN sed -i 's/# \(en_US.UTF-8\)/\1/' /etc/locale.gen && \
  /usr/sbin/locale-gen

# Set root password
RUN echo "root:${root_password}" | chpasswd

# Add user
RUN useradd -ms /bin/bash ${user} && \
  chown -R ${user}:${user} /home/${user} && \
  ulimit -n 100000
# Add new user to sudoers file without password
RUN echo "${user} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER ${user}
WORKDIR /home/${user}/
ENV LC_ALL en_US.UTF-8
ENV TERM xterm-256color

# Install Rust
RUN curl https://sh.rustup.rs -sSf | \
  sh -s -- --default-toolchain stable -y
ENV PATH=/home/${user}/.cargo/bin:$PATH

RUN mkdir qscan
COPY Cargo.lock qscan/Cargo.lock
COPY Cargo.toml qscan/Cargo.toml
ADD bin qscan/bin
ADD src qscan/src
RUN cd qscan && cargo build --release && \
  sudo cp target/release/tcp_cs /bin/ && \
  cd .. && sudo rm -rf qscan

ENTRYPOINT ["/bin/tcp_cs"]


