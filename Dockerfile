FROM rust:latest AS builder

WORKDIR /app

COPY Cargo.toml .
COPY src/ ./src/

RUN cargo build --release

FROM debian:buster-slim
WORKDIR /app
COPY --from=builder /app/target/release/ldap-authd .
ENTRYPOINT ["./ldap-authd"]

