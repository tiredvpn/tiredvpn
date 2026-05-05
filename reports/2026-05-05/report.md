# TiredVPN Availability Report — 2026-05-05

**Date:** 2026-05-05  |  **Version:** 1.1.1

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_1 | 90ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_3 | 81ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_4 | 125ms |
| MegaFon → Hetzner Nuremberg | 15 | 4 | confusion_0 | 104ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 108ms | ✅ 133ms |
| REALITY Protocol | ✅ 196ms | ✅ 221ms |
| HTTP Polling (meek-style) | ✅ 133ms | ✅ 168ms |
| HTTP/2 Steganography | ✅ 128ms | ❌ — |
| WebSocket Salamander | ❌ — | ✅ 162ms |
| Traffic Morph (Yandex Video) | ✅ 981ms | ✅ 965ms |
| Traffic Morph (VK Video) | ✅ 977ms | ✅ 991ms |
| Traffic Morph (Baidu Video) | ✅ 977ms | ✅ 985ms |
| Traffic Morph (Aparat Video) | ✅ 980ms | ✅ 970ms |
| Geneva (Russia TSPU) | ✅ 144ms | ✅ 179ms |
| Geneva (China GFW) | ✅ 161ms | ✅ 179ms |
| Geneva (Iran DPI) | ✅ 141ms | ✅ 165ms |
| Anti-Probe Resistance | ✅ 892ms | ✅ 939ms |
| Protocol Confusion (DNS/TLS) | ✅ 103ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 90ms | ✅ 126ms |
| Protocol Confusion (SSH/TLS) | ✅ 99ms | ✅ 131ms |
| Protocol Confusion (SMTP/TLS) | ✅ 104ms | ✅ 132ms |
| Protocol Confusion (Multi-Layer) | ✅ 97ms | ✅ 125ms |
| State Table Exhaustion | ✅ 2087ms | ✅ 2097ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 87ms | ✅ 124ms |
| REALITY Protocol | ✅ 172ms | ✅ 202ms |
| HTTP Polling (meek-style) | ✅ 117ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 124ms | ✅ 141ms |
| WebSocket Salamander | ✅ 125ms | ✅ 164ms |
| Traffic Morph (Yandex Video) | ❌ — | ❌ — |
| Traffic Morph (VK Video) | ❌ — | ❌ — |
| Traffic Morph (Baidu Video) | ❌ — | ❌ — |
| Traffic Morph (Aparat Video) | ❌ — | ❌ — |
| Geneva (Russia TSPU) | ✅ 163ms | ✅ 162ms |
| Geneva (China GFW) | ✅ 153ms | ✅ 165ms |
| Geneva (Iran DPI) | ✅ 125ms | ✅ 164ms |
| Anti-Probe Resistance | ✅ 888ms | ✅ 897ms |
| Protocol Confusion (DNS/TLS) | ✅ 92ms | ✅ 104ms |
| Protocol Confusion (HTTP/TLS) | ✅ 83ms | ✅ 1113ms |
| Protocol Confusion (SSH/TLS) | ✅ 85ms | ✅ 123ms |
| Protocol Confusion (SMTP/TLS) | ✅ 81ms | ✅ 124ms |
| Protocol Confusion (Multi-Layer) | ✅ 86ms | ✅ 117ms |
| State Table Exhaustion | ✅ 2078ms | ✅ 2085ms |

---
*Generated automatically.*
