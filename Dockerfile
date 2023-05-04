FROM rust:latest AS builder

WORKDIR /app

COPY Cargo.toml .
COPY src/ ./src/

RUN cargo build --release

FROM debian:buster-slim
WORKDIR /app
COPY --from=builder /app/target/release/ldap-authd .

RUN apt-get update && \
    apt-get install -y libssl1.1 && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["./ldap-authd"]

