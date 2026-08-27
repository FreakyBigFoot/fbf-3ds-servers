FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata tcpdump
WORKDIR /app
COPY ffe-server-linux-amd64 /app/ffe-server
COPY certs /app/certs
ENV FFE_NASC_ADDR=":443" \
    FFE_AUTH_PORT="61001" \
    FFE_SECURE_PORT="61002" \
    FFE_TLS_CERT="/app/certs/nasc.crt" \
    FFE_TLS_KEY="/app/certs/nasc.key"
EXPOSE 443/tcp 61001/udp 61002/udp
ENTRYPOINT ["/app/ffe-server"]
