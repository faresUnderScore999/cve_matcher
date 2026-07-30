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

RUN apk add --no-cache ca-certificates tzdata dcron

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/matcher .

# Create crontab: run matcher daily at 5am, redirect output to Docker logs
RUN echo "0 5 * * * /app/matcher > /proc/1/fd/1 2>&1" > /var/spool/cron/crontabs/root

# Start cron in foreground (keeps container alive and logs to stdout)
CMD ["crond", "-f", "-l", "2"]