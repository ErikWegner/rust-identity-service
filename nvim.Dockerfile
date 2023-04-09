FROM rust:1.68.2-alpine

# Prepare environment

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN apk add bash git lua nodejs npm lazygit bottom python3 go neovim ripgrep alpine-sdk --update

# Prepare user
ARG GID=1000
RUN addgroup -g ${GID} coder
RUN adduser -g '' -G coder -D coder
#RUN adduser coder sudo
#RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Run as user
USER coder
WORKDIR /workspace
RUN mkdir -p /home/coder/.config/nvim && mkdir -p /home/coder/.local/state && mkdir -p /home/coder/.local/share
RUN rustup component add clippy && rustup component add rustfmt && cargo install cargo-nextest --locked && cargo install cargo-watch

# Local commands (outside docker)
# mkdir -p ~/.config/nvim
# mkdir -p ~/.config/TabNine
# mkdir -p ~/.local/share/nvim
# mkdir -p ~/.local/state/nvim
# git clone --depth 1 https://github.com/AstroNvim/AstroNvim ~/.config/nvim
