# TiredVPN Availability Report — 2026-06-14

**Date:** 2026-06-14  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_3 | 96ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_4 | 86ms |
| MegaFon → Hetzner Amsterdam | 16 | 3 | confusion_0 | 474ms |
| MegaFon → Hetzner Nuremberg | 12 | 7 | confusion_1 | 293ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 110ms | ✅ 558ms |
| REALITY Protocol | ✅ 195ms | ✅ 534ms |
| HTTP Polling (meek-style) | ✅ 130ms | ❌ — |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 141ms | ✅ 582ms |
| Traffic Morph (Yandex Video) | ✅ 143ms | ✅ 582ms |
| Traffic Morph (VK Video) | ✅ 133ms | ✅ 660ms |
| Traffic Morph (Baidu Video) | ✅ 139ms | ✅ 582ms |
| Traffic Morph (Aparat Video) | ✅ 141ms | ✅ 577ms |
| Geneva (Russia TSPU) | ✅ 164ms | ✅ 581ms |
| Geneva (China GFW) | ✅ 149ms | ✅ 677ms |
| Geneva (Iran DPI) | ✅ 135ms | ❌ — |
| Anti-Probe Resistance | ✅ 896ms | ✅ 1382ms |
| Protocol Confusion (DNS/TLS) | ✅ 111ms | ✅ 474ms |
| Protocol Confusion (HTTP/TLS) | ✅ 110ms | ✅ 528ms |
| Protocol Confusion (SSH/TLS) | ✅ 99ms | ✅ 504ms |
| Protocol Confusion (SMTP/TLS) | ✅ 96ms | ✅ 546ms |
| Protocol Confusion (Multi-Layer) | ✅ 1151ms | ✅ 534ms |
| State Table Exhaustion | ✅ 2096ms | ✅ 2206ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 94ms | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 138ms | ❌ — |
| HTTP/2 Steganography | ✅ 136ms | ❌ — |
| WebSocket Salamander | ✅ 121ms | ✅ 467ms |
| Traffic Morph (Yandex Video) | ✅ 123ms | ✅ 526ms |
| Traffic Morph (VK Video) | ✅ 139ms | ✅ 467ms |
| Traffic Morph (Baidu Video) | ✅ 130ms | ✅ 543ms |
| Traffic Morph (Aparat Video) | ✅ 135ms | ✅ 555ms |
| Geneva (Russia TSPU) | ✅ 144ms | ✅ 561ms |
| Geneva (China GFW) | ✅ 137ms | ✅ 566ms |
| Geneva (Iran DPI) | ✅ 140ms | ❌ — |
| Anti-Probe Resistance | ✅ 908ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 100ms | ✅ 372ms |
| Protocol Confusion (HTTP/TLS) | ✅ 94ms | ✅ 293ms |
| Protocol Confusion (SSH/TLS) | ✅ 94ms | ✅ 451ms |
| Protocol Confusion (SMTP/TLS) | ✅ 92ms | ✅ 451ms |
| Protocol Confusion (Multi-Layer) | ✅ 86ms | ✅ 451ms |
| State Table Exhaustion | ✅ 2078ms | ❌ — |

---
*Generated automatically.*
