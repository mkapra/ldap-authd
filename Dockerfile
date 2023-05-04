FROM rust:latest AS builder

WORKDIR /app

COPY Cargo.toml .
COPY src/ ./src/

RUN cargo build --release

RUN apt-get update && \
    apt-get install -y libssl1.1 && \
    rm -rf /var/lib/apt/lists/*

FROM debian:buster-slim
WORKDIR /app
COPY --from=builder /app/target/release/ldap-authd .
ENTRYPOINT ["./ldap-authd"]

