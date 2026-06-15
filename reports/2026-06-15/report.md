# TiredVPN Availability Report — 2026-06-15

**Date:** 2026-06-15  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_4 | 93ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_1 | 78ms |
| MegaFon → Hetzner Amsterdam | 16 | 3 | confusion_0 | 473ms |
| MegaFon → Hetzner Nuremberg | 13 | 6 | confusion_3 | 277ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 125ms | ✅ 843ms |
| REALITY Protocol | ✅ 216ms | ✅ 762ms |
| HTTP Polling (meek-style) | ✅ 145ms | ❌ — |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 163ms | ✅ 877ms |
| Traffic Morph (Yandex Video) | ✅ 143ms | ✅ 855ms |
| Traffic Morph (VK Video) | ✅ 137ms | ✅ 877ms |
| Traffic Morph (Baidu Video) | ✅ 134ms | ✅ 889ms |
| Traffic Morph (Aparat Video) | ✅ 142ms | ✅ 877ms |
| Geneva (Russia TSPU) | ✅ 173ms | ✅ 876ms |
| Geneva (China GFW) | ✅ 190ms | ✅ 894ms |
| Geneva (Iran DPI) | ✅ 170ms | ❌ — |
| Anti-Probe Resistance | ✅ 931ms | ✅ 1487ms |
| Protocol Confusion (DNS/TLS) | ✅ 107ms | ✅ 473ms |
| Protocol Confusion (HTTP/TLS) | ✅ 131ms | ✅ 603ms |
| Protocol Confusion (SSH/TLS) | ✅ 118ms | ✅ 801ms |
| Protocol Confusion (SMTP/TLS) | ✅ 103ms | ✅ 762ms |
| Protocol Confusion (Multi-Layer) | ✅ 93ms | ✅ 762ms |
| State Table Exhaustion | ✅ 2084ms | ✅ 2202ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 92ms | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 141ms | ❌ — |
| HTTP/2 Steganography | ✅ 132ms | ❌ — |
| WebSocket Salamander | ✅ 129ms | ✅ 594ms |
| Traffic Morph (Yandex Video) | ✅ 121ms | ✅ 538ms |
| Traffic Morph (VK Video) | ✅ 134ms | ✅ 554ms |
| Traffic Morph (Baidu Video) | ✅ 115ms | ✅ 538ms |
| Traffic Morph (Aparat Video) | ✅ 143ms | ✅ 538ms |
| Geneva (Russia TSPU) | ✅ 150ms | ✅ 553ms |
| Geneva (China GFW) | ✅ 126ms | ✅ 582ms |
| Geneva (Iran DPI) | ✅ 124ms | ❌ — |
| Anti-Probe Resistance | ✅ 899ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 86ms | ✅ 374ms |
| Protocol Confusion (HTTP/TLS) | ✅ 78ms | ✅ 392ms |
| Protocol Confusion (SSH/TLS) | ✅ 97ms | ✅ 349ms |
| Protocol Confusion (SMTP/TLS) | ✅ 85ms | ✅ 277ms |
| Protocol Confusion (Multi-Layer) | ✅ 91ms | ✅ 312ms |
| State Table Exhaustion | ✅ 2086ms | ✅ 2178ms |

---
*Generated automatically.*
