#!/usr/bin/env bash
# ci-benchmark.sh — localhost server+client benchmark for CI
# Starts server with self-signed cert, runs client benchmark against it.
set -euo pipefail

PORT=19995
LISTEN="127.0.0.1:${PORT}"
SECRET="ci-bench-secret-$(date +%s)"
TMPDIR=$(mktemp -d)
CERT="${TMPDIR}/server.crt"
KEY="${TMPDIR}/server.key"
FAKEWEB="${TMPDIR}/www"
SERVER_LOG="${TMPDIR}/server.log"
SERVER_PID=""
BINARY="./tiredvpn"

cleanup() {
    local exit_code=$?
    set +e
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null
        wait "${SERVER_PID}" 2>/dev/null
    fi
    if [[ ${exit_code} -ne 0 ]] && [[ -f "${SERVER_LOG}" ]]; then
        echo "=== SERVER LOG (last 50 lines) ==="
        tail -n 50 "${SERVER_LOG}" || true
        echo "=== END SERVER LOG ==="
    fi
    rm -rf "${TMPDIR}"
    exit "${exit_code}"
}
trap cleanup EXIT

echo ">>> Generating self-signed TLS certificate"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${KEY}" -out "${CERT}" -days 1 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    2>/dev/null

echo ">>> Building binary"
go build -o "${BINARY}" ./cmd/tiredvpn/

echo ">>> Creating fake web root"
mkdir -p "${FAKEWEB}"
echo "<html><body>ok</body></html>" > "${FAKEWEB}/index.html"

echo ">>> Starting server on ${LISTEN}"
"${BINARY}" server \
    -listen "${LISTEN}" \
    -cert "${CERT}" \
    -key "${KEY}" \
    -secret "${SECRET}" \
    -fake-root "${FAKEWEB}" \
    -no-quic \
    -enable-v6=false \
    -dual-stack=false \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

echo ">>> Waiting for server (pid ${SERVER_PID}) to be ready..."
DEADLINE=$((SECONDS + 30))
while ! nc -z 127.0.0.1 "${PORT}" 2>/dev/null; do
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "ERROR: server process died"
        exit 1
    fi
    if (( SECONDS >= DEADLINE )); then
        echo "ERROR: server did not become ready within 30s"
        exit 1
    fi
    sleep 0.3
done
echo ">>> Server is ready"

echo ">>> Running client benchmark"
"${BINARY}" client \
    -server "${LISTEN}" \
    -secret "${SECRET}" \
    -listen "127.0.0.1:0" \
    -cover "localhost" \
    -benchmark
BENCH_EXIT=$?

echo ">>> Benchmark finished (exit code: ${BENCH_EXIT})"
exit "${BENCH_EXIT}"
