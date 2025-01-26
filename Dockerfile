## Build ridser binary
FROM rust:1.84.0-alpine3.20 AS builder

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
WORKDIR /usr/src
RUN USER=root cargo new ridser
COPY Cargo.toml Cargo.lock /usr/src/ridser/
WORKDIR /usr/src/ridser/
RUN apk add --no-cache musl-dev && rustup target add x86_64-unknown-linux-musl
RUN update-ca-certificates
RUN cargo build --target x86_64-unknown-linux-musl --release
COPY src /usr/src/ridser/src/
RUN touch /usr/src/ridser/src/main.rs
RUN cargo build --target x86_64-unknown-linux-musl --release
RUN strip -s /usr/src/ridser/target/x86_64-unknown-linux-musl/release/ridser

## Final image
FROM alpine:3.20 AS runtime
ENV MIMALLOC_LARGE_OS_PAGES=1
COPY --from=builder /usr/src/ridser/target/x86_64-unknown-linux-musl/release/ridser /
EXPOSE 3000
VOLUME ["/files"]
USER 65534
CMD ["/ridser"]
