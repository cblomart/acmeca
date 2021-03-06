FROM golang:1.14-alpine3.11 AS builder

RUN apk add --no-cache gcc musl-dev upx

WORKDIR /app

COPY . .

RUN go build ./cmd/acmeca.go

RUN upx -qq acmeca

FROM alpine:3.11

RUN apk add --no-cache curl

COPY --from=builder /app/acmeca /usr/local/bin/acmeca

RUN apk add --no-cache libcap && \
    setcap 'cap_net_bind_service=ep' /usr/local/bin/acmeca && \
    apk del libcap

RUN addgroup -g 1001 -S acmeca && adduser -u 1001 -D -S -G acmeca acmeca

RUN mkdir -p /etc/acmeca/certs && \
    mkdir -p /var/acmeca/certs && \
    chown -R acmeca:acmeca /etc/acmeca && \
    chown -R acmeca:acmeca /var/acmeca

VOLUME [ "/etc/acmeca", "/var/acmeca" ]

EXPOSE 8443/tcp

USER acmeca

ENTRYPOINT ["/usr/local/bin/acmeca"]


