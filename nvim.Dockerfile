FROM rust:1.68.2

# Prepare environment

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN apt update && apt upgrade -y
RUN curl -LO https://github.com/BurntSushi/ripgrep/releases/download/13.0.0/ripgrep_13.0.0_amd64.deb
RUN dpkg -i ripgrep_13.0.0_amd64.deb
RUN curl -LO https://github.com/neovim/neovim/releases/download/v0.8.3/nvim-linux64.deb
RUN dpkg -i nvim-linux64.deb
RUN apt install sudo tmux

# Prepare user
ARG GID=1001
RUN addgroup --gid ${GID} coder
RUN adduser --gecos '' --gid ${GID} --disabled-password coder
RUN adduser coder sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Run as user
USER coder
WORKDIR /workspace
RUN mkdir -p /home/coder/.config/nvim
RUN rustup component add clippy && rustup component add rustfmt && cargo install cargo-nextest --locked && cargo install cargo-watch

# Local commands
# mkdir -p ~/.config/nvim
# mkdir -p ~/.config/TabNine
# mkdir -p ~/.local/share/nvim
# git clone --depth 1 https://github.com/wbthomason/packer.nvim  ~/.local/share/nvim/site/pack/packer/start/packer.nvim
