# NAT-PMP HTTP Server

A lightweight HTTP API server for NAT-PMP (Network Address Translation Port Mapping Protocol) port forwarding that enables containerized and standalone applications to request and maintain port mappings through VPN gateways.

## Why This Exists

**Security**: Instead of giving every application dangerous network privileges (`NET_ADMIN`, `NET_RAW`), only this one server needs them. Applications use a simple HTTP API instead.

**Simplicity**: No need to implement complex NAT-PMP protocol in each application. Works with any language that can make HTTP requests.

**Target use case**: VPN running directly on host nodes with multiple applications needing port forwarding (common in Kubernetes, home labs, etc.)

## Features

- **Native Rust performance** - Fast, memory-safe implementation
- **HTTP API** for NAT-PMP operations (no need for applications to implement NAT-PMP directly)
- **Multi-architecture support** - Binaries and containers for x86_64, ARM64, ARMv7, and RISC-V
- **Automatic port mapping management** with configurable duration and heartbeat
- **Minimal footprint** - ~12MB Alpine-based multi-arch container with static binary
- **Kubernetes-friendly** with proper health probes and DaemonSet deployment
- **Flexible configuration** via CLI arguments or environment variables
- **Bearer token authentication** for secure access (environment variable recommended)

## Quick Start

### Docker

```bash
docker run -d \
  --name natpmp-http-api \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -e NATPMP_GATEWAY=10.2.0.1 \
  -e API_TOKEN=your-secret-token \
  ghcr.io/BohdanTkachenko/natpmp-http-api:latest
```

**Note:** Use `--network host` for NAT-PMP to work properly. Port mapping (`-p 8080:8080`) won't work for NAT-PMP operations.

### Direct Binary

```bash
# Download pre-built binary from GitHub releases
# Choose your architecture:
# - natpmp-http-api-linux-amd64 (x86_64 - most servers/desktops)
# - natpmp-http-api-linux-arm64 (ARM64 - Raspberry Pi 3/4/5, ARM servers)
# - natpmp-http-api-linux-armv7 (ARMv7 - Raspberry Pi 2/3)
# - natpmp-http-api-linux-riscv64 (RISC-V 64-bit)

wget https://github.com/BohdanTkachenko/natpmp-http-api/releases/latest/download/natpmp-http-api-linux-amd64
chmod +x natpmp-http-api-linux-amd64

# Run with authentication (environment variable recommended for security)
API_TOKEN=your-secret-token ./natpmp-http-api-linux-amd64 --gateway=10.2.0.1

# Or build locally
cargo build --release
./target/release/natpmp-http-api --gateway=10.2.0.1 --port=8080
```

## ⚠️ Important: Heartbeat Required

NAT-PMP mappings expire automatically. You **must** send periodic requests to maintain them:

```bash
# Request mapping with authentication (60-second duration)
curl -X POST http://localhost:8080/forward \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer your-secret-token' \
  -d '{"internal_port": 6881, "protocol": "tcp", "duration": 60}'

# Repeat every 45 seconds to maintain the mapping (before 60s expiration)
# Recommended: Send heartbeat at 75% of duration (45s for 60s mapping)
```

Response:

```json
{
  "internal_port": 6881,
  "external_port": 62610,
  "protocol": "tcp", 
  "duration": 60
}
```

## API Reference

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/forward` | POST | Request/renew port mapping | Yes (if token set) |
| `/health` | GET | Health check | No |

## Configuration

| CLI Argument | Environment Variable | Required | Default | Description |
|--------------|---------------------|----------|---------|-------------|
| `--gateway` | `NATPMP_GATEWAY` | ✅ | - | VPN gateway IP address |
| `--port` | `API_PORT` | | 8080 | Server port |
| `--bind-address` | `API_BIND_ADDRESS` | | 0.0.0.0 | Server bind address |
| `--max-duration` | `NATPMP_MAX_DURATION` | | 300 | Maximum mapping duration (-1 to disable) |
| `--log-level` | `LOG_LEVEL` | | info | Log level (debug/info/warning/error) |
|  | `API_TOKEN` | | - | Bearer token for authentication (optional) |

**Notes:**

- CLI arguments take precedence over environment variables
- Authentication is enabled when `API_TOKEN` is set
- For containers, environment variables are typically more convenient

## Use Cases

### VPN Port Forwarding

Perfect for applications running behind VPN connections (like ProtonVPN, NordVPN, etc.) that need to expose ports to the internet:

- BitTorrent clients (qBittorrent, Transmission, etc.)
- Game servers
- Development servers
- Remote access applications

### Kubernetes Integration

The server runs as a DaemonSet on nodes with VPN connections, allowing pods to request port mappings:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: natpmp
spec:
  selector:
    matchLabels:
      app: natpmp
  template:
    metadata:
      labels:
        app: natpmp
    spec:
      hostNetwork: true
      containers:
      - name: natpmp-http-api
        image: ghcr.io/BohdanTkachenko/natpmp-http-api:latest
        env:
        - name: NATPMP_GATEWAY
          value: "10.2.0.1"
        - name: API_TOKEN
          valueFrom:
            secretKeyRef:
              name: natpmp-secret
              key: token
        securityContext:
          capabilities:
            add: ["NET_ADMIN", "NET_RAW"]
        ports:
        - containerPort: 8080
          name: http
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: natpmp
spec:
  selector:
    app: natpmp
  ports:
  - port: 8080
    name: http
```

### Kubernetes Sidecar Example

For Kubernetes deployments, use a sidecar container to handle heartbeats:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: my-app
        image: my-app:latest
        ports:
        - containerPort: 6881
      
      # Sidecar container for NAT-PMP heartbeat
      - name: natpmp-heartbeat
        image: alpine/curl:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          while true; do
            echo "Sending NAT-PMP heartbeat..."
            curl -X POST http://natpmp-service:8080/forward \
              -H 'Content-Type: application/json' \
              -H 'Authorization: Bearer $API_TOKEN' \
              -d '{"internal_port": 6881, "protocol": "tcp", "duration": 60}' \
              --max-time 30 || echo "Heartbeat failed"
            sleep 45  # Renew every 45 seconds (before 60s expiration)
          done
        resources:
          limits:
            cpu: 50m
            memory: 32Mi
```

## Security Considerations

**⚠️ This server runs with elevated network privileges and can expose ports to the internet.**

### Risks

- High privilege process that could be exploited
- Opens external ports on your VPN gateway
- Could be used for denial of service attacks

### Mitigation

- Restrict network access to the server (use firewalls, NetworkPolicies)
- Monitor port mappings and set reasonable duration limits
- Keep the container image updated (automatic daily builds include security patches)
- Deploy on isolated network segments when possible

## Requirements

**Runtime:**

- `libnatpmp` library (for static binaries)
- VPN connection with NAT-PMP support
- Network capabilities (`NET_ADMIN`, `NET_RAW` for containers)

**Development:**

- Rust 1.78+ (for building from source)
- `libnatpmp-dev` (build dependency)

**Production:**

- **Containers**: No additional dependencies (libnatpmp included)
- **Static binaries**: Requires `libnatpmp` on target system

## Building

### Automated Builds

**Container images** are automatically built and published to GitHub Container Registry:

- **Architectures**: linux/amd64, linux/arm64, linux/arm/v7, linux/riscv64
- **On releases**: Tagged versions (e.g., `v1.0.0`)
- **On code changes**: Latest builds from main branch
- **Weekly security updates**: Base image updates via Dependabot

**Binaries** are automatically built for all architectures and attached to GitHub releases:
- x86_64 (amd64) - Most servers and desktops
- ARM64 (aarch64) - Raspberry Pi 3/4/5, ARM servers
- ARMv7 - Raspberry Pi 2/3, older ARM devices
- RISC-V 64-bit - VisionFive, BeagleV, RISC-V SBCs

All binaries include SHA256 checksums for verification.

### Local Development

```bash
# Build and test the binary
cargo build --release
./target/release/natpmp-http-api --help

# Build container for testing
docker build -t natpmp-http-api .
```

### Using Pre-built Artifacts

**Container images:**

```bash
# Multi-arch images (automatically pulls correct architecture)
# Supports: linux/amd64, linux/arm64, linux/arm/v7, linux/riscv64
docker pull ghcr.io/BohdanTkachenko/natpmp-http-api:latest
docker pull ghcr.io/BohdanTkachenko/natpmp-http-api:v1.0.0
```

**Static binaries:**

```bash
# Install runtime dependency first
# Ubuntu/Debian:
sudo apt-get install libnatpmp
# Alpine:
apk add libnatpmp

# Download from GitHub releases (choose your architecture)
# For x86_64:
wget https://github.com/BohdanTkachenko/natpmp-http-api/releases/latest/download/natpmp-http-api-linux-amd64
chmod +x natpmp-http-api-linux-amd64

# For ARM64:
# wget https://github.com/BohdanTkachenko/natpmp-http-api/releases/latest/download/natpmp-http-api-linux-arm64

# For ARMv7:
# wget https://github.com/BohdanTkachenko/natpmp-http-api/releases/latest/download/natpmp-http-api-linux-armv7

# For RISC-V 64-bit:
# wget https://github.com/BohdanTkachenko/natpmp-http-api/releases/latest/download/natpmp-http-api-linux-riscv64

# Verify checksums
sha256sum -c natpmp-http-api-linux-amd64.sha256
```

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
