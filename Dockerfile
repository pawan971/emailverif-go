# Build stage
FROM golang:alpine AS builder

WORKDIR /app

# Copy go mod file
COPY go.mod ./
# If there were go.sum, copy it too
# COPY go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o emailverif-web .

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/emailverif-web .

# Copy templates
COPY templates/ ./templates/

# Expose port
EXPOSE 8080

# Command to run
CMD ["./emailverif-web"]
