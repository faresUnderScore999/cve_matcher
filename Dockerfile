# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the matcher binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/matcher ./cmd/matcher/

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/matcher .

# Copy .env file if present (for local development)
COPY .env* ./

# Run the matcher
ENTRYPOINT ["/app/matcher"]
