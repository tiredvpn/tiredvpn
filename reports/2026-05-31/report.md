# TiredVPN Availability Report — 2026-05-31

**Date:** 2026-05-31  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_3 | 90ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 79ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 123ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_3 | 99ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 102ms | ✅ 140ms |
| REALITY Protocol | ✅ 198ms | ✅ 228ms |
| HTTP Polling (meek-style) | ✅ 153ms | ✅ 186ms |
| HTTP/2 Steganography | ✅ 145ms | ✅ 171ms |
| WebSocket Salamander | ✅ 161ms | ✅ 169ms |
| Traffic Morph (Yandex Video) | ✅ 129ms | ✅ 162ms |
| Traffic Morph (VK Video) | ✅ 128ms | ✅ 179ms |
| Traffic Morph (Baidu Video) | ✅ 157ms | ✅ 177ms |
| Traffic Morph (Aparat Video) | ✅ 138ms | ✅ 171ms |
| Geneva (Russia TSPU) | ✅ 138ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 129ms | ✅ 183ms |
| Geneva (Iran DPI) | ✅ 144ms | ✅ 189ms |
| Anti-Probe Resistance | ✅ 882ms | ✅ 935ms |
| Protocol Confusion (DNS/TLS) | ✅ 107ms | ✅ 123ms |
| Protocol Confusion (HTTP/TLS) | ✅ 112ms | ✅ 129ms |
| Protocol Confusion (SSH/TLS) | ✅ 98ms | ✅ 129ms |
| Protocol Confusion (SMTP/TLS) | ✅ 90ms | ✅ 134ms |
| Protocol Confusion (Multi-Layer) | ✅ 108ms | ✅ 133ms |
| State Table Exhaustion | ✅ 2087ms | ✅ 2100ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 92ms | ✅ 111ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 135ms | ✅ 170ms |
| HTTP/2 Steganography | ✅ 133ms | ✅ 167ms |
| WebSocket Salamander | ✅ 117ms | ✅ 136ms |
| Traffic Morph (Yandex Video) | ✅ 116ms | ✅ 135ms |
| Traffic Morph (VK Video) | ✅ 131ms | ✅ 168ms |
| Traffic Morph (Baidu Video) | ✅ 133ms | ✅ 148ms |
| Traffic Morph (Aparat Video) | ✅ 136ms | ✅ 171ms |
| Geneva (Russia TSPU) | ✅ 163ms | ✅ 171ms |
| Geneva (China GFW) | ✅ 121ms | ✅ 170ms |
| Geneva (Iran DPI) | ✅ 116ms | ✅ 169ms |
| Anti-Probe Resistance | ✅ 896ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 87ms | ✅ 122ms |
| Protocol Confusion (HTTP/TLS) | ✅ 87ms | ✅ 108ms |
| Protocol Confusion (SSH/TLS) | ✅ 82ms | ✅ 117ms |
| Protocol Confusion (SMTP/TLS) | ✅ 79ms | ✅ 99ms |
| Protocol Confusion (Multi-Layer) | ✅ 82ms | ✅ 101ms |
| State Table Exhaustion | ✅ 2080ms | ✅ 2096ms |

---
*Generated automatically.*
