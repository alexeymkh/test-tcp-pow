FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -o server ./cmd/main.go

FROM scratch
COPY --from=builder /app/server /app/
ENTRYPOINT ["/app/server"]
