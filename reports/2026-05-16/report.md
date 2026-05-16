# TiredVPN Availability Report — 2026-05-16

**Date:** 2026-05-16  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_4 | 102ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | confusion_4 | 87ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_2 | 125ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_1 | 117ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 120ms | ✅ 130ms |
| REALITY Protocol | ✅ 212ms | ✅ 241ms |
| HTTP Polling (meek-style) | ✅ 139ms | ✅ 196ms |
| HTTP/2 Steganography | ✅ 198ms | ✅ 182ms |
| WebSocket Salamander | ✅ 154ms | ✅ 191ms |
| Traffic Morph (Yandex Video) | ✅ 127ms | ✅ 193ms |
| Traffic Morph (VK Video) | ✅ 142ms | ✅ 193ms |
| Traffic Morph (Baidu Video) | ✅ 130ms | ✅ 164ms |
| Traffic Morph (Aparat Video) | ✅ 138ms | ✅ 190ms |
| Geneva (Russia TSPU) | ✅ 188ms | ✅ 190ms |
| Geneva (China GFW) | ✅ 183ms | ✅ 193ms |
| Geneva (Iran DPI) | ✅ 142ms | ✅ 196ms |
| Anti-Probe Resistance | ✅ 918ms | ✅ 904ms |
| Protocol Confusion (DNS/TLS) | ✅ 107ms | ✅ 137ms |
| Protocol Confusion (HTTP/TLS) | ✅ 111ms | ✅ 125ms |
| Protocol Confusion (SSH/TLS) | ✅ 114ms | ✅ 125ms |
| Protocol Confusion (SMTP/TLS) | ✅ 117ms | ✅ 126ms |
| Protocol Confusion (Multi-Layer) | ✅ 102ms | ✅ 131ms |
| State Table Exhaustion | ✅ 2121ms | ✅ 2111ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 152ms | ✅ 118ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 139ms | ✅ 168ms |
| HTTP/2 Steganography | ✅ 135ms | ✅ 147ms |
| WebSocket Salamander | ✅ 130ms | ✅ 146ms |
| Traffic Morph (Yandex Video) | ✅ 131ms | ✅ 172ms |
| Traffic Morph (VK Video) | ✅ 145ms | ✅ 145ms |
| Traffic Morph (Baidu Video) | ✅ 128ms | ✅ 145ms |
| Traffic Morph (Aparat Video) | ✅ 585ms | ✅ 167ms |
| Geneva (Russia TSPU) | ✅ 125ms | ✅ 169ms |
| Geneva (China GFW) | ✅ 198ms | ✅ 166ms |
| Geneva (Iran DPI) | ✅ 210ms | ✅ 170ms |
| Anti-Probe Resistance | ❌ — | ✅ 914ms |
| Protocol Confusion (DNS/TLS) | ✅ 100ms | ✅ 122ms |
| Protocol Confusion (HTTP/TLS) | ✅ 101ms | ✅ 117ms |
| Protocol Confusion (SSH/TLS) | ✅ 144ms | ✅ 125ms |
| Protocol Confusion (SMTP/TLS) | ✅ 99ms | ✅ 126ms |
| Protocol Confusion (Multi-Layer) | ✅ 87ms | ✅ 121ms |
| State Table Exhaustion | ✅ 2085ms | ✅ 2110ms |

---
*Generated automatically.*
