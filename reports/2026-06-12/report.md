# TiredVPN Availability Report — 2026-06-12

**Date:** 2026-06-12  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_1 | 101ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_4 | 78ms |
| MegaFon → Hetzner Amsterdam | 16 | 3 | confusion_1 | 218ms |
| MegaFon → Hetzner Nuremberg | 3 | 16 | geneva_china | 548ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 124ms | ✅ 342ms |
| REALITY Protocol | ✅ 216ms | ✅ 324ms |
| HTTP Polling (meek-style) | ✅ 160ms | ❌ — |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 152ms | ✅ 359ms |
| Traffic Morph (Yandex Video) | ✅ 144ms | ✅ 437ms |
| Traffic Morph (VK Video) | ✅ 137ms | ✅ 444ms |
| Traffic Morph (Baidu Video) | ✅ 143ms | ✅ 443ms |
| Traffic Morph (Aparat Video) | ✅ 137ms | ✅ 443ms |
| Geneva (Russia TSPU) | ✅ 186ms | ✅ 460ms |
| Geneva (China GFW) | ✅ 144ms | ✅ 341ms |
| Geneva (Iran DPI) | ✅ 139ms | ❌ — |
| Anti-Probe Resistance | ✅ 913ms | ✅ 1100ms |
| Protocol Confusion (DNS/TLS) | ✅ 111ms | ✅ 305ms |
| Protocol Confusion (HTTP/TLS) | ✅ 101ms | ✅ 218ms |
| Protocol Confusion (SSH/TLS) | ✅ 105ms | ✅ 263ms |
| Protocol Confusion (SMTP/TLS) | ✅ 117ms | ✅ 299ms |
| Protocol Confusion (Multi-Layer) | ✅ 121ms | ✅ 323ms |
| State Table Exhaustion | ✅ 2088ms | ✅ 2188ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 99ms | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 130ms | ❌ — |
| HTTP/2 Steganography | ✅ 132ms | ❌ — |
| WebSocket Salamander | ✅ 139ms | ✅ 624ms |
| Traffic Morph (Yandex Video) | ✅ 133ms | ❌ — |
| Traffic Morph (VK Video) | ✅ 132ms | ❌ — |
| Traffic Morph (Baidu Video) | ✅ 124ms | ❌ — |
| Traffic Morph (Aparat Video) | ✅ 116ms | ❌ — |
| Geneva (Russia TSPU) | ✅ 193ms | ✅ 624ms |
| Geneva (China GFW) | ✅ 117ms | ✅ 548ms |
| Geneva (Iran DPI) | ✅ 138ms | ❌ — |
| Anti-Probe Resistance | ✅ 892ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 83ms | ❌ — |
| Protocol Confusion (HTTP/TLS) | ✅ 91ms | ❌ — |
| Protocol Confusion (SSH/TLS) | ✅ 88ms | ❌ — |
| Protocol Confusion (SMTP/TLS) | ✅ 92ms | ❌ — |
| Protocol Confusion (Multi-Layer) | ✅ 78ms | ❌ — |
| State Table Exhaustion | ✅ 2090ms | ❌ — |

---
*Generated automatically.*
