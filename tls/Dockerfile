FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates libssl-dev openssl pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY common.h common.c tls_server.c tls_benchmark.c Makefile ./
RUN openssl list -tls1_3 -tls-groups | tr ':' '\n' | grep -qx X25519MLKEM768 \
    && make \
    && mkdir -p /opt/tls/bin /opt/tls/certs \
    && cp tls_server tls_benchmark /opt/tls/bin/ \
    && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
         -subj "/CN=hybrid-tls-lab" \
         -addext "subjectAltName=DNS:localhost,DNS:classical-tls,DNS:hybrid-tls,DNS:hybrid-p256-tls,IP:127.0.0.1" \
         -keyout /opt/tls/certs/server.key -out /opt/tls/certs/server.crt \
    && chmod 600 /opt/tls/certs/server.key

COPY benchmark-entrypoint.sh /opt/tls/bin/benchmark-entrypoint
RUN chmod 755 /opt/tls/bin/benchmark-entrypoint \
    && useradd --create-home --uid 1000 tlslab \
    && chown -R tlslab:tlslab /opt/tls

USER tlslab
WORKDIR /opt/tls

