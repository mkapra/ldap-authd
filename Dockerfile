FROM rust:1.70-bookworm AS builder

WORKDIR /app

COPY Cargo.toml .
COPY src/ ./src/

RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/ldap-authd .

RUN apt-get update && apt-get install -y \
  libssl3 \
  && rm -rf /var/lib/apt/lists/*

CMD ["./ldap-authd", "--hostname", "0.0.0.0"]

