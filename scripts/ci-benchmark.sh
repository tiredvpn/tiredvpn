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

CLIENT_PID=""

cleanup() {
    local exit_code=$?
    set +e
    if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
        kill "${CLIENT_PID}" 2>/dev/null
        wait "${CLIENT_PID}" 2>/dev/null
    fi
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

echo ""
echo "=== Phase 2: E2E Data Flow Test ==="

# Start client in normal proxy mode (not benchmark).
# Use -strategy reality to skip adaptive probing (which takes 30s+).
# REALITY works over TLS on localhost and is always registered.
CLIENT_PROXY_PORT=11080
"${BINARY}" client \
    -server "${LISTEN}" \
    -secret "${SECRET}" \
    -listen "127.0.0.1:${CLIENT_PROXY_PORT}" \
    -cover "localhost" \
    -strategy "reality" \
    &>"${TMPDIR}/client-proxy.log" &
CLIENT_PID=$!

echo ">>> Waiting for SOCKS5 proxy on :${CLIENT_PROXY_PORT}..."
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 "${CLIENT_PROXY_PORT}" 2>/dev/null; then
        echo ">>> SOCKS5 proxy ready after ${i}s"
        break
    fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
        echo "ERROR: Client died. Log:"
        cat "${TMPDIR}/client-proxy.log"
        exit 1
    fi
    sleep 1
done

if ! nc -z 127.0.0.1 "${CLIENT_PROXY_PORT}" 2>/dev/null; then
    echo "ERROR: SOCKS5 proxy did not start within 60s"
    cat "${TMPDIR}/client-proxy.log"
    exit 1
fi

E2E_PASS=false

# Test 1: HTTP request through tunnel (httpbin JSON API)
echo ">>> Test 1: HTTP GET through SOCKS5 proxy"
HTTP_RESPONSE=$(curl -s -x socks5h://127.0.0.1:${CLIENT_PROXY_PORT} \
    --connect-timeout 10 --max-time 15 \
    http://httpbin.org/get 2>&1) || true

if echo "${HTTP_RESPONSE}" | grep -q '"origin"'; then
    echo ">>> PASS: HTTP request returned valid JSON response"
    E2E_PASS=true
else
    echo ">>> FAIL: HTTP response invalid (httpbin may be unreachable)"
    echo "Response: ${HTTP_RESPONSE}"
fi

# Test 2: Download known page and verify content
echo ">>> Test 2: Download test through SOCKS5 proxy"
curl -s -x socks5h://127.0.0.1:${CLIENT_PROXY_PORT} \
    --connect-timeout 10 --max-time 30 \
    -o "${TMPDIR}/testfile" \
    http://www.example.com/ 2>&1 || true

if [ -s "${TMPDIR}/testfile" ] && grep -q "Example Domain" "${TMPDIR}/testfile"; then
    echo ">>> PASS: Downloaded content verified"
    E2E_PASS=true
else
    echo ">>> FAIL: Download verification failed"
    if [ -f "${TMPDIR}/testfile" ]; then
        echo "File size: $(wc -c < "${TMPDIR}/testfile")"
    else
        echo "No file downloaded"
    fi
fi

# Cleanup client
kill "${CLIENT_PID}" 2>/dev/null || true
wait "${CLIENT_PID}" 2>/dev/null || true
CLIENT_PID=""

if [[ "${E2E_PASS}" != "true" ]]; then
    echo ""
    echo ">>> WARNING: Both E2E tests failed. Client log (last 30 lines):"
    tail -n 30 "${TMPDIR}/client-proxy.log" || true
fi

echo ""
echo "=== E2E Result: ${E2E_PASS} ==="

# E2E failure is non-fatal for CI (external sites may be unreachable)
exit "${BENCH_EXIT}"
