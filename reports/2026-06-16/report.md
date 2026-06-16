# TiredVPN Availability Report — 2026-06-16

**Date:** 2026-06-16  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_3 | 107ms |
| Rostelecom → Hetzner Nuremberg | 14 | 5 | confusion_0 | 86ms |
| MegaFon → Hetzner Amsterdam | 15 | 4 | confusion_1 | 520ms |
| MegaFon → Hetzner Nuremberg | 13 | 6 | confusion_2 | 255ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ❌ — | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ❌ — | ❌ — |
| HTTP/2 Steganography | ✅ 174ms | ✅ 762ms |
| WebSocket Salamander | ✅ 174ms | ✅ 762ms |
| Traffic Morph (Yandex Video) | ✅ 151ms | ✅ 653ms |
| Traffic Morph (VK Video) | ✅ 155ms | ✅ 647ms |
| Traffic Morph (Baidu Video) | ✅ 155ms | ✅ 653ms |
| Traffic Morph (Aparat Video) | ✅ 155ms | ✅ 647ms |
| Geneva (Russia TSPU) | ✅ 171ms | ✅ 647ms |
| Geneva (China GFW) | ✅ 170ms | ✅ 653ms |
| Geneva (Iran DPI) | ✅ 193ms | ❌ — |
| Anti-Probe Resistance | ✅ 949ms | ✅ 1432ms |
| Protocol Confusion (DNS/TLS) | ✅ 141ms | ✅ 562ms |
| Protocol Confusion (HTTP/TLS) | ✅ 140ms | ✅ 520ms |
| Protocol Confusion (SSH/TLS) | ✅ 139ms | ✅ 536ms |
| Protocol Confusion (SMTP/TLS) | ✅ 107ms | ✅ 562ms |
| Protocol Confusion (Multi-Layer) | ✅ 128ms | ✅ 605ms |
| State Table Exhaustion | ✅ 2101ms | ✅ 2233ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ❌ — | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ❌ — | ❌ — |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 136ms | ✅ 345ms |
| Traffic Morph (Yandex Video) | ✅ 140ms | ✅ 345ms |
| Traffic Morph (VK Video) | ✅ 121ms | ✅ 351ms |
| Traffic Morph (Baidu Video) | ✅ 124ms | ✅ 415ms |
| Traffic Morph (Aparat Video) | ✅ 128ms | ✅ 346ms |
| Geneva (Russia TSPU) | ✅ 178ms | ✅ 414ms |
| Geneva (China GFW) | ✅ 135ms | ✅ 356ms |
| Geneva (Iran DPI) | ✅ 143ms | ❌ — |
| Anti-Probe Resistance | ❌ — | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 86ms | ✅ 309ms |
| Protocol Confusion (HTTP/TLS) | ✅ 97ms | ✅ 255ms |
| Protocol Confusion (SSH/TLS) | ✅ 91ms | ✅ 255ms |
| Protocol Confusion (SMTP/TLS) | ✅ 96ms | ✅ 255ms |
| Protocol Confusion (Multi-Layer) | ✅ 89ms | ✅ 260ms |
| State Table Exhaustion | ✅ 2090ms | ✅ 2211ms |

---
*Generated automatically.*
