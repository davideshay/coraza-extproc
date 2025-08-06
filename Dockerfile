# Use multi-stage build with specific Go version
FROM --platform=$BUILDPLATFORM golang:alpine3.22 AS builder

# Install git for fetching dependencies (if needed)
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

RUN git clone --depth 1 --branch v4.0.0 https://github.com/corazawaf/coraza-coreruleset.git /opt/owasp-crs && \
    mkdir -p /etc/coraza/conf && \
    cp -r /opt/owasp-crs/rules /etc/coraza/ && \
    cp /opt/owasp-crs/rules/crs-setup.conf.example /etc/coraza/crs-setup.conf

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies with cache mount
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Build arguments for cross-compilation
ARG TARGETOS
ARG TARGETARCH

# Build the application with cache mounts and optimizations
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o main .

# Final stage - minimal runtime image
FROM alpine:3.22

# Copy CA certificates and timezone data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /app/main /main
COPY --from=builder /etc/coraza /etc/coraza

RUN mkdir -p /etc/coraza/rules

# Expose port (adjust as needed)
EXPOSE 9000

# Run the binary
ENTRYPOINT ["/main"]