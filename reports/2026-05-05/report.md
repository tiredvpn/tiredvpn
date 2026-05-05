# TiredVPN Availability Report — 2026-05-05

**Date:** 2026-05-05  |  **Version:** 1.1.1

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 17 | 2 | confusion_2 | 164ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_2 | 78ms |
| MegaFon → Hetzner Amsterdam | 17 | 2 | confusion_1 | 122ms |
| MegaFon → Hetzner Nuremberg | 19 | 0 | confusion_0 | 104ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 166ms | ✅ 130ms |
| REALITY Protocol | ✅ 338ms | ✅ 190ms |
| HTTP Polling (meek-style) | ✅ 220ms | ✅ 145ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ❌ — | ❌ — |
| Traffic Morph (Yandex Video) | ✅ 975ms | ✅ 144ms |
| Traffic Morph (VK Video) | ✅ 978ms | ✅ 161ms |
| Traffic Morph (Baidu Video) | ✅ 972ms | ✅ 168ms |
| Traffic Morph (Aparat Video) | ✅ 975ms | ✅ 178ms |
| Geneva (Russia TSPU) | ✅ 290ms | ✅ 176ms |
| Geneva (China GFW) | ✅ 217ms | ✅ 172ms |
| Geneva (Iran DPI) | ✅ 217ms | ✅ 166ms |
| Anti-Probe Resistance | ✅ 975ms | ✅ 929ms |
| Protocol Confusion (DNS/TLS) | ✅ 172ms | ✅ 124ms |
| Protocol Confusion (HTTP/TLS) | ✅ 169ms | ✅ 122ms |
| Protocol Confusion (SSH/TLS) | ✅ 164ms | ✅ 131ms |
| Protocol Confusion (SMTP/TLS) | ✅ 178ms | ✅ 130ms |
| Protocol Confusion (Multi-Layer) | ✅ 176ms | ✅ 123ms |
| State Table Exhaustion | ✅ 2091ms | ✅ 2098ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 85ms | ✅ 116ms |
| REALITY Protocol | ✅ 177ms | ✅ 194ms |
| HTTP Polling (meek-style) | ✅ 119ms | ✅ 161ms |
| HTTP/2 Steganography | ✅ 133ms | ✅ 146ms |
| WebSocket Salamander | ✅ 118ms | ✅ 165ms |
| Traffic Morph (Yandex Video) | ❌ — | ✅ 139ms |
| Traffic Morph (VK Video) | ❌ — | ✅ 151ms |
| Traffic Morph (Baidu Video) | ❌ — | ✅ 164ms |
| Traffic Morph (Aparat Video) | ❌ — | ✅ 142ms |
| Geneva (Russia TSPU) | ✅ 118ms | ✅ 141ms |
| Geneva (China GFW) | ✅ 117ms | ✅ 168ms |
| Geneva (Iran DPI) | ✅ 119ms | ✅ 165ms |
| Anti-Probe Resistance | ✅ 883ms | ✅ 904ms |
| Protocol Confusion (DNS/TLS) | ✅ 86ms | ✅ 104ms |
| Protocol Confusion (HTTP/TLS) | ✅ 86ms | ✅ 112ms |
| Protocol Confusion (SSH/TLS) | ✅ 78ms | ✅ 114ms |
| Protocol Confusion (SMTP/TLS) | ✅ 83ms | ✅ 111ms |
| Protocol Confusion (Multi-Layer) | ✅ 79ms | ✅ 113ms |
| State Table Exhaustion | ✅ 2085ms | ✅ 2101ms |

---
*Generated automatically.*
