# TiredVPN Availability Report — 2026-06-09

**Date:** 2026-06-09  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_4 | 108ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | confusion_3 | 82ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 126ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_0 | 105ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 131ms | ✅ 138ms |
| REALITY Protocol | ✅ 201ms | ✅ 227ms |
| HTTP Polling (meek-style) | ✅ 169ms | ✅ 163ms |
| HTTP/2 Steganography | ❌ — | ✅ 154ms |
| WebSocket Salamander | ✅ 164ms | ✅ 176ms |
| Traffic Morph (Yandex Video) | ✅ 134ms | ✅ 178ms |
| Traffic Morph (VK Video) | ✅ 141ms | ✅ 178ms |
| Traffic Morph (Baidu Video) | ✅ 142ms | ✅ 172ms |
| Traffic Morph (Aparat Video) | ✅ 141ms | ✅ 168ms |
| Geneva (Russia TSPU) | ✅ 195ms | ✅ 169ms |
| Geneva (China GFW) | ✅ 150ms | ✅ 177ms |
| Geneva (Iran DPI) | ✅ 174ms | ✅ 183ms |
| Anti-Probe Resistance | ✅ 904ms | ✅ 943ms |
| Protocol Confusion (DNS/TLS) | ✅ 109ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 125ms | ✅ 136ms |
| Protocol Confusion (SSH/TLS) | ✅ 113ms | ✅ 134ms |
| Protocol Confusion (SMTP/TLS) | ✅ 116ms | ✅ 126ms |
| Protocol Confusion (Multi-Layer) | ✅ 108ms | ✅ 131ms |
| State Table Exhaustion | ✅ 2090ms | ✅ 2112ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 84ms | ✅ 116ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 130ms | ✅ 169ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 123ms | ✅ 160ms |
| Traffic Morph (Yandex Video) | ✅ 125ms | ✅ 171ms |
| Traffic Morph (VK Video) | ✅ 124ms | ✅ 170ms |
| Traffic Morph (Baidu Video) | ✅ 118ms | ✅ 143ms |
| Traffic Morph (Aparat Video) | ✅ 117ms | ✅ 148ms |
| Geneva (Russia TSPU) | ✅ 137ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 128ms | ✅ 168ms |
| Geneva (Iran DPI) | ✅ 142ms | ✅ 164ms |
| Anti-Probe Resistance | ✅ 893ms | ✅ 915ms |
| Protocol Confusion (DNS/TLS) | ✅ 83ms | ✅ 105ms |
| Protocol Confusion (HTTP/TLS) | ✅ 84ms | ✅ 116ms |
| Protocol Confusion (SSH/TLS) | ✅ 89ms | ✅ 117ms |
| Protocol Confusion (SMTP/TLS) | ✅ 82ms | ✅ 119ms |
| Protocol Confusion (Multi-Layer) | ✅ 90ms | ✅ 108ms |
| State Table Exhaustion | ✅ 2088ms | ✅ 2097ms |

---
*Generated automatically.*
