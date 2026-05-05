# scripts/local/Dockerfile
FROM golang:1.25-alpine AS builder

# FIX: Install git so 'go mod download' can fetch from GitHub
RUN apk add --no-cache git

WORKDIR /app

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /ledger ./cmd/ledger

# Minimal runtime image
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /
COPY --from=builder /ledger /ledger

EXPOSE 8080
ENTRYPOINT ["/ledger"]