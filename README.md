# Hybrid TLS Performance Lab

An academic demonstration that performs real TLS 1.3 handshakes with OpenSSL and compares:

- Classical key exchange: `X25519`
- Hybrid post-quantum/traditional key exchange: `X25519MLKEM768`

The project includes two deliberately identical TLS endpoints, an OpenSSL C benchmark client, a server-side handshake timer, a FastAPI ingestion service, SQLite persistence, CSV export, and a live comparison dashboard.

> Demonstration only. The generated certificate is self-signed and embedded in the local TLS image. This project is not a security-hardened proxy, production load generator, FIPS-validation claim, or capacity-planning tool.

## Architecture

```text
                         ┌────────────────────────────────────┐
                         │ FastAPI dashboard :8000            │
                         │ SQLite + percentiles + CSV export  │
                         └──────────────▲───────────▲─────────┘
                                        │           │
                           server metric│           │client metric
                                        │           │
┌──────────────────┐       TLS 1.3      │           │
│ OpenSSL C client ├───────────────┬────┘           │
│ alternating A/B  │               │                │
└──────────────────┘               │                │
             ┌─────────────────────┴──────────────────────┐
             │                                            │
   ┌─────────▼────────────┐                    ┌──────────▼─────────────┐
   │ Classical TLS :4433  │                    │ Hybrid TLS :4434       │
   │ group: X25519        │                    │ group: X25519MLKEM768  │
   │ times SSL_accept()   │                    │ times SSL_accept()     │
   └──────────────────────┘                    └────────────────────────┘
```

Both endpoints use:

- The same OpenSSL build and container image.
- TLS 1.3 only.
- The same certificate and certificate-signature algorithm.
- The same TLS cipher policy.
- Session caches and TLS 1.3 session tickets disabled.
- A single forced key-exchange group, preventing fallback or HelloRetryRequest from contaminating the comparison.

## Quick start

Requirements: Docker Engine and Docker Compose v2.

```bash
docker compose up --build -d
docker compose ps
docker compose run --rm benchmark-client
```

Open the dashboard at <http://localhost:8000>.

The default run performs 10 unrecorded warmups followed by 100 recorded fresh connections per mode. Increase the sample count with:

```bash
ITERATIONS=1000 WARMUP=50 docker compose run --rm benchmark-client
```

Give a run a stable identifier:

```bash
docker compose run --rm benchmark-client --run-id local-arm64-baseline
```

Download the currently selected run through the dashboard or directly:

```bash
curl -o results.csv 'http://localhost:8000/api/results.csv?run_id=local-arm64-baseline'
```

Stop the services without deleting measurements:

```bash
docker compose down
```

The named `benchmark-data` volume retains SQLite data. To intentionally erase all benchmark history, use `docker compose down -v`.

## Metrics

Every measured connection uses a unique sample ID shared by the client and TLS server.

| Metric | Measurement boundary |
|---|---|
| Client TCP | Immediately before `connect()` to successful TCP connection |
| Client TLS | Immediately before `SSL_connect()` to successful completion |
| Server TLS | Immediately before `SSL_accept()` to successful completion |
| Client TTFB | Before TCP connect to first application-response byte |
| Client total | Before TCP connect through complete response read |
| Bytes sent/received | OpenSSL network BIO counters for the connection |

The dashboard reports median, p95, p99, minimum, maximum, mean, failures, byte counts, and the hybrid-versus-classical median difference. Raw samples remain exportable as CSV.

## Why this is a fairer comparison

Standard hybrid TLS does not require a custom extra half round trip. The client sends its hybrid key share in `ClientHello`, and the server returns its hybrid share in `ServerHello`. Both configurations therefore use the normal TLS 1.3 flight structure when the correct share is offered initially.

The benchmark client alternates execution order:

```text
iteration 1: classical → hybrid
iteration 2: hybrid → classical
iteration 3: classical → hybrid
...
```

This reduces systematic drift from CPU temperature, scheduling, or background load. It still does not eliminate noise, so use percentile distributions and multiple independent runs.

## Verify negotiated groups manually

Classical:

```bash
openssl s_client \
  -connect localhost:4433 \
  -tls1_3 \
  -groups X25519 \
  -CAfile tls-local.crt \
  -brief
```

Hybrid:

```bash
openssl s_client \
  -connect localhost:4434 \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -CAfile tls-local.crt \
  -brief
```

The certificate lives inside the TLS image. To copy it for host-side inspection:

```bash
docker compose cp classical-tls:/opt/tls/certs/server.crt ./tls-local.crt
```

Your host OpenSSL must be 3.5 or newer to recognize `X25519MLKEM768`. The Docker workflow does not depend on the host OpenSSL version.

## Controlled network experiments

Start with Docker-network/loopback measurements to emphasize cryptographic and software cost. For network sensitivity, deploy the client and servers on different hosts or introduce controlled network conditions and record them in the run ID.

Recommended experiment matrix:

| Variable | Suggested values |
|---|---|
| RTT | 0, 10, 40, 80 ms |
| Loss | 0%, 0.1%, 1% |
| MTU | 1500, 1280 bytes |
| Concurrency | 1 first; add load only as a separate experiment |
| Samples | 1,000+ per mode per condition |

The larger hybrid `ClientHello` can cross packet boundaries, so MTU and packet loss may matter more than primitive cryptographic time on real networks.

Do not mix resumed and full handshakes. This demo disables resumption so every sample measures a fresh key exchange.

## Local development

Dashboard tests:

```bash
cd dashboard
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

Compile the C programs against a local OpenSSL 3.5+ installation:

```bash
cd tls
make check-groups
make
```

The local client defaults to Docker service hostnames. Use explicit host endpoints when running it outside Docker:

```bash
./tls_benchmark \
  --classical-host localhost --classical-port 4433 \
  --hybrid-host localhost --hybrid-port 4434 \
  --dashboard-host localhost --dashboard-port 8000 \
  --cafile ./tls-local.crt \
  --iterations 100 --warmup 10
```

## Standards and implementation notes

- ML-KEM is standardized in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
- Hybrid key exchange construction for TLS 1.3 is described by [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html).
- `X25519MLKEM768` is registered in the [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml).
- OpenSSL 3.5 and later provide native standardized ML-KEM and hybrid TLS groups. This project uses that native TLS implementation; it does not implement a custom combiner.

