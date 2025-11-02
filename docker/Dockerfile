# Build stage
FROM golang:1.25-alpine AS builder

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

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    curl

# Install Trivy using the official install script
# This method is more reliable than downloading tar.gz directly
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

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

