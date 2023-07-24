FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -o client ./main.go

FROM scratch
COPY --from=builder /app/client /app/
ENTRYPOINT ["/app/client"]
