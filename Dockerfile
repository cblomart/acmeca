FROM golang:1.14-alpine3.11 AS builder

RUN apk add --no-cache gcc musl-dev upx

WORKDIR /app

COPY . .

RUN go build ./cmd/acmeca.go

RUN upx -qq acmeca

FROM alpine:3.11

RUN apk add --no-cache curl

COPY --from=builder /app/acmeca /usr/local/bin/acmeca

RUN mkdir -p /etc/acmeca/certs && \
    mkdir -p /var/acmeca/certs

VOLUME [ "/etc/acmeca", "/var/acmeca" ]

EXPOSE 8443/tcp

ENTRYPOINT ["/usr/local/bin/acmeca"]


