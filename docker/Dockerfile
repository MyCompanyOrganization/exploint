# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install git for go modules
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o exploint \
    ./cmd/exploint

# Runtime stage
FROM alpine:latest

# Install Trivy and required tools
RUN apk add --no-cache \
    ca-certificates \
    curl \
    && curl -sfL https://github.com/aquasecurity/trivy/releases/latest/download/trivy_$(uname -s)_$(uname -m).tar.gz | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -S exploint && adduser -S exploint -G exploint

# Copy binary from builder
COPY --from=builder /build/exploint /usr/local/bin/exploint

# Set working directory
WORKDIR /workspace

# Switch to non-root user
USER exploint

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/exploint"]

