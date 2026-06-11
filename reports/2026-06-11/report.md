# TiredVPN Availability Report — 2026-06-11

**Date:** 2026-06-11  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_0 | 128ms |
| Rostelecom → Hetzner Nuremberg | 16 | 3 | confusion_0 | 78ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_1 | 122ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_4 | 104ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 349ms | ✅ 151ms |
| REALITY Protocol | ✅ 436ms | ✅ 508ms |
| HTTP Polling (meek-style) | ✅ 289ms | ✅ 194ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 293ms | ✅ 200ms |
| Traffic Morph (Yandex Video) | ✅ 343ms | ✅ 201ms |
| Traffic Morph (VK Video) | ✅ 340ms | ✅ 198ms |
| Traffic Morph (Baidu Video) | ✅ 342ms | ✅ 199ms |
| Traffic Morph (Aparat Video) | ✅ 348ms | ✅ 201ms |
| Geneva (Russia TSPU) | ✅ 418ms | ✅ 201ms |
| Geneva (China GFW) | ✅ 309ms | ✅ 470ms |
| Geneva (Iran DPI) | ✅ 345ms | ✅ 200ms |
| Anti-Probe Resistance | ✅ 940ms | ✅ 920ms |
| Protocol Confusion (DNS/TLS) | ✅ 128ms | ✅ 123ms |
| Protocol Confusion (HTTP/TLS) | ✅ 155ms | ✅ 122ms |
| Protocol Confusion (SSH/TLS) | ✅ 136ms | ✅ 142ms |
| Protocol Confusion (SMTP/TLS) | ✅ 162ms | ✅ 135ms |
| Protocol Confusion (Multi-Layer) | ✅ 167ms | ✅ 147ms |
| State Table Exhaustion | ✅ 2143ms | ✅ 2117ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 101ms | ✅ 120ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 117ms | ✅ 163ms |
| HTTP/2 Steganography | ❌ — | ✅ 141ms |
| WebSocket Salamander | ✅ 125ms | ✅ 192ms |
| Traffic Morph (Yandex Video) | ✅ 121ms | ✅ 142ms |
| Traffic Morph (VK Video) | ✅ 123ms | ✅ 150ms |
| Traffic Morph (Baidu Video) | ✅ 126ms | ✅ 141ms |
| Traffic Morph (Aparat Video) | ✅ 137ms | ✅ 168ms |
| Geneva (Russia TSPU) | ✅ 164ms | ✅ 176ms |
| Geneva (China GFW) | ✅ 135ms | ✅ 162ms |
| Geneva (Iran DPI) | ✅ 116ms | ✅ 164ms |
| Anti-Probe Resistance | ❌ — | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 78ms | ✅ 117ms |
| Protocol Confusion (HTTP/TLS) | ✅ 84ms | ✅ 125ms |
| Protocol Confusion (SSH/TLS) | ✅ 97ms | ✅ 116ms |
| Protocol Confusion (SMTP/TLS) | ✅ 87ms | ✅ 120ms |
| Protocol Confusion (Multi-Layer) | ✅ 87ms | ✅ 104ms |
| State Table Exhaustion | ✅ 2082ms | ❌ — |

---
*Generated automatically.*
