# TiredVPN Availability Report — 2026-06-07

**Date:** 2026-06-07  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_1 | 98ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | quic_salamander | 82ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_1 | 175ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_0 | 123ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 113ms | ✅ 176ms |
| REALITY Protocol | ✅ 205ms | ✅ 286ms |
| HTTP Polling (meek-style) | ✅ 144ms | ✅ 286ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 134ms | ✅ 355ms |
| Traffic Morph (Yandex Video) | ✅ 125ms | ✅ 241ms |
| Traffic Morph (VK Video) | ✅ 143ms | ✅ 241ms |
| Traffic Morph (Baidu Video) | ✅ 134ms | ✅ 285ms |
| Traffic Morph (Aparat Video) | ✅ 143ms | ✅ 241ms |
| Geneva (Russia TSPU) | ✅ 172ms | ✅ 285ms |
| Geneva (China GFW) | ✅ 146ms | ✅ 284ms |
| Geneva (Iran DPI) | ✅ 153ms | ✅ 284ms |
| Anti-Probe Resistance | ✅ 921ms | ✅ 1044ms |
| Protocol Confusion (DNS/TLS) | ✅ 108ms | ✅ 193ms |
| Protocol Confusion (HTTP/TLS) | ✅ 98ms | ✅ 175ms |
| Protocol Confusion (SSH/TLS) | ✅ 115ms | ✅ 176ms |
| Protocol Confusion (SMTP/TLS) | ✅ 108ms | ✅ 193ms |
| Protocol Confusion (Multi-Layer) | ✅ 105ms | ✅ 194ms |
| State Table Exhaustion | ✅ 2090ms | ✅ 2179ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 82ms | ✅ 340ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 135ms | ✅ 571ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 118ms | ✅ 168ms |
| Traffic Morph (Yandex Video) | ✅ 122ms | ✅ 189ms |
| Traffic Morph (VK Video) | ✅ 117ms | ✅ 169ms |
| Traffic Morph (Baidu Video) | ✅ 122ms | ✅ 560ms |
| Traffic Morph (Aparat Video) | ✅ 131ms | ✅ 613ms |
| Geneva (Russia TSPU) | ✅ 116ms | ✅ 179ms |
| Geneva (China GFW) | ✅ 132ms | ✅ 229ms |
| Geneva (Iran DPI) | ✅ 141ms | ✅ 179ms |
| Anti-Probe Resistance | ✅ 883ms | ✅ 1402ms |
| Protocol Confusion (DNS/TLS) | ✅ 84ms | ✅ 123ms |
| Protocol Confusion (HTTP/TLS) | ✅ 83ms | ✅ 199ms |
| Protocol Confusion (SSH/TLS) | ✅ 87ms | ✅ 128ms |
| Protocol Confusion (SMTP/TLS) | ✅ 91ms | ✅ 1190ms |
| Protocol Confusion (Multi-Layer) | ✅ 83ms | ✅ 137ms |
| State Table Exhaustion | ✅ 2086ms | ❌ — |

---
*Generated automatically.*
