# Stage 1: Build
FROM golang:alpine-3.22 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o coraza-ext-waf .

# Stage 2: Runtime
FROM alpine:3.22

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/coraza-ext-waf .
COPY --from=builder /app/waf ./waf

EXPOSE 50051

ENTRYPOINT ["./coraza-ext-waf"]
