# TiredVPN Availability Report — 2026-06-04

**Date:** 2026-06-04  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_4 | 87ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_4 | 79ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_1 | 105ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_3 | 108ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 109ms | ✅ 131ms |
| REALITY Protocol | ✅ 203ms | ✅ 214ms |
| HTTP Polling (meek-style) | ✅ 135ms | ✅ 172ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 150ms | ✅ 186ms |
| Traffic Morph (Yandex Video) | ✅ 141ms | ✅ 148ms |
| Traffic Morph (VK Video) | ✅ 139ms | ✅ 154ms |
| Traffic Morph (Baidu Video) | ✅ 130ms | ✅ 158ms |
| Traffic Morph (Aparat Video) | ✅ 129ms | ✅ 175ms |
| Geneva (Russia TSPU) | ✅ 175ms | ✅ 169ms |
| Geneva (China GFW) | ✅ 136ms | ✅ 180ms |
| Geneva (Iran DPI) | ✅ 153ms | ✅ 177ms |
| Anti-Probe Resistance | ✅ 921ms | ✅ 926ms |
| Protocol Confusion (DNS/TLS) | ✅ 98ms | ✅ 180ms |
| Protocol Confusion (HTTP/TLS) | ✅ 104ms | ✅ 105ms |
| Protocol Confusion (SSH/TLS) | ✅ 101ms | ✅ 130ms |
| Protocol Confusion (SMTP/TLS) | ✅ 111ms | ✅ 123ms |
| Protocol Confusion (Multi-Layer) | ✅ 87ms | ✅ 134ms |
| State Table Exhaustion | ✅ 2093ms | ✅ 2114ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 85ms | ✅ 127ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 120ms | ✅ 178ms |
| HTTP/2 Steganography | ✅ 141ms | ✅ 172ms |
| WebSocket Salamander | ✅ 134ms | ✅ 166ms |
| Traffic Morph (Yandex Video) | ✅ 135ms | ✅ 172ms |
| Traffic Morph (VK Video) | ✅ 124ms | ✅ 173ms |
| Traffic Morph (Baidu Video) | ✅ 136ms | ✅ 142ms |
| Traffic Morph (Aparat Video) | ✅ 133ms | ✅ 167ms |
| Geneva (Russia TSPU) | ✅ 152ms | ✅ 175ms |
| Geneva (China GFW) | ✅ 172ms | ✅ 178ms |
| Geneva (Iran DPI) | ✅ 131ms | ✅ 167ms |
| Anti-Probe Resistance | ✅ 883ms | ✅ 925ms |
| Protocol Confusion (DNS/TLS) | ✅ 85ms | ✅ 116ms |
| Protocol Confusion (HTTP/TLS) | ✅ 91ms | ✅ 122ms |
| Protocol Confusion (SSH/TLS) | ✅ 89ms | ✅ 124ms |
| Protocol Confusion (SMTP/TLS) | ✅ 93ms | ✅ 108ms |
| Protocol Confusion (Multi-Layer) | ✅ 79ms | ✅ 115ms |
| State Table Exhaustion | ✅ 2083ms | ✅ 2094ms |

---
*Generated automatically.*
