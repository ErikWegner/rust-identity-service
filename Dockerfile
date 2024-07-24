## Build stage
## Build mimalloc
FROM alpine:3.20 as mimallocbuilder
RUN apk add git build-base cmake linux-headers
RUN cd /; git clone --depth 1 https://github.com/microsoft/mimalloc; cd mimalloc; mkdir build; cd build; cmake ..; make -j$(nproc); make install

## Build ridser binary
FROM rust:1.79.0-alpine AS builder

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

## Put together final image
FROM alpine:3.20 AS runtime
COPY --from=mimallocbuilder /mimalloc/build/*.so.* /lib/
RUN ln -s /lib/libmimalloc.so.2.1 /lib/libmimalloc.so
ENV LD_PRELOAD=/lib/libmimalloc.so
ENV MIMALLOC_LARGE_OS_PAGES=1
COPY --from=builder /usr/src/ridser/target/x86_64-unknown-linux-musl/release/ridser /
EXPOSE 3000
VOLUME ["/files"]
USER 65534
CMD ["/ridser"]
