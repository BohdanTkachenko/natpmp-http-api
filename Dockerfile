FROM rust:1.91-slim AS builder

ARG TARGETARCH
ARG TARGETVARIANT

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
        "amd64")  RUST_TARGET="x86_64-unknown-linux-musl" ;; \
        "arm64")  RUST_TARGET="aarch64-unknown-linux-musl" ;; \
        "arm") \
            case "$TARGETVARIANT" in \
                "v7") RUST_TARGET="armv7-unknown-linux-musleabihf" ;; \
                *)    echo "Unsupported ARM variant: $TARGETVARIANT"; exit 1 ;; \
            esac ;; \
        "riscv64") RUST_TARGET="riscv64gc-unknown-linux-gnu" ;; \
        *)        echo "Unsupported architecture: $TARGETARCH"; exit 1 ;; \
    esac && \
    echo "$RUST_TARGET" > /tmp/rust-target && \
    rustup target add $RUST_TARGET

WORKDIR /build

COPY Cargo.toml Cargo.lock src ./
COPY src ./src
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo build --release --target $RUST_TARGET && \
    cp target/$RUST_TARGET/release/natpmp-http-api natpmp-http-api && \
    strip natpmp-http-api && \
    chmod +x natpmp-http-api 

FROM alpine:3.22

WORKDIR /app
COPY --from=builder /build/natpmp-http-api .

ENV API_BIND_ADDRESS=0.0.0.0
ENV API_PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["./natpmp-http-api"]