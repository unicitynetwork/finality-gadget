FROM golang:1.26-bookworm AS builder

# Prepare libgcc for the final distroless image
RUN mkdir -p /target/lib && cp /lib/$(uname -m)-linux-gnu/libgcc_s.so.1 /target/lib/libgcc_s.so.1

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary with CGO enabled for secp256k1
RUN CGO_ENABLED=1 \
    go build -trimpath -ldflags="-s -w" -o /app/fgp ./cmd


#  Runtime
FROM gcr.io/distroless/base-debian13:debug-nonroot

WORKDIR /app

COPY --from=builder /app/fgp /app/fgp
COPY --from=builder /target/lib/libgcc_s.so.1 /lib/libgcc_s.so.1

USER nonroot

ENTRYPOINT ["/app/fgp"]
