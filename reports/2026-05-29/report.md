# TiredVPN Availability Report — 2026-05-29

**Date:** 2026-05-29  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_0 | 88ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_0 | 79ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 118ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_2 | 106ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 109ms | ✅ 140ms |
| REALITY Protocol | ✅ 202ms | ✅ 222ms |
| HTTP Polling (meek-style) | ✅ 129ms | ✅ 185ms |
| HTTP/2 Steganography | ✅ 135ms | ✅ 176ms |
| WebSocket Salamander | ✅ 133ms | ✅ 170ms |
| Traffic Morph (Yandex Video) | ✅ 130ms | ✅ 161ms |
| Traffic Morph (VK Video) | ✅ 126ms | ✅ 177ms |
| Traffic Morph (Baidu Video) | ✅ 128ms | ✅ 171ms |
| Traffic Morph (Aparat Video) | ✅ 138ms | ✅ 183ms |
| Geneva (Russia TSPU) | ✅ 155ms | ✅ 176ms |
| Geneva (China GFW) | ✅ 165ms | ✅ 176ms |
| Geneva (Iran DPI) | ✅ 158ms | ✅ 180ms |
| Anti-Probe Resistance | ✅ 906ms | ✅ 948ms |
| Protocol Confusion (DNS/TLS) | ✅ 88ms | ✅ 118ms |
| Protocol Confusion (HTTP/TLS) | ✅ 99ms | ✅ 129ms |
| Protocol Confusion (SSH/TLS) | ✅ 101ms | ✅ 136ms |
| Protocol Confusion (SMTP/TLS) | ✅ 95ms | ✅ 123ms |
| Protocol Confusion (Multi-Layer) | ✅ 97ms | ✅ 124ms |
| State Table Exhaustion | ✅ 2084ms | ✅ 2107ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 92ms | ✅ 118ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 121ms | ✅ 141ms |
| HTTP/2 Steganography | ✅ 131ms | ✅ 170ms |
| WebSocket Salamander | ✅ 123ms | ✅ 166ms |
| Traffic Morph (Yandex Video) | ✅ 128ms | ✅ 135ms |
| Traffic Morph (VK Video) | ✅ 115ms | ✅ 172ms |
| Traffic Morph (Baidu Video) | ✅ 113ms | ✅ 173ms |
| Traffic Morph (Aparat Video) | ✅ 125ms | ✅ 172ms |
| Geneva (Russia TSPU) | ✅ 117ms | ✅ 160ms |
| Geneva (China GFW) | ✅ 117ms | ✅ 138ms |
| Geneva (Iran DPI) | ✅ 135ms | ✅ 166ms |
| Anti-Probe Resistance | ✅ 875ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 79ms | ✅ 113ms |
| Protocol Confusion (HTTP/TLS) | ✅ 82ms | ✅ 119ms |
| Protocol Confusion (SSH/TLS) | ✅ 81ms | ✅ 106ms |
| Protocol Confusion (SMTP/TLS) | ✅ 83ms | ✅ 108ms |
| Protocol Confusion (Multi-Layer) | ✅ 83ms | ✅ 113ms |
| State Table Exhaustion | ✅ 2085ms | ❌ — |

---
*Generated automatically.*
