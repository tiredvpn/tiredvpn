# TiredVPN Availability Report — 2026-05-28

**Date:** 2026-05-28  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_1 | 111ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 78ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 115ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_1 | 100ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 136ms | ✅ 135ms |
| REALITY Protocol | ✅ 256ms | ✅ 225ms |
| HTTP Polling (meek-style) | ✅ 180ms | ✅ 179ms |
| HTTP/2 Steganography | ✅ 180ms | ✅ 174ms |
| WebSocket Salamander | ✅ 154ms | ✅ 178ms |
| Traffic Morph (Yandex Video) | ✅ 128ms | ✅ 183ms |
| Traffic Morph (VK Video) | ✅ 149ms | ✅ 172ms |
| Traffic Morph (Baidu Video) | ✅ 131ms | ✅ 170ms |
| Traffic Morph (Aparat Video) | ✅ 136ms | ✅ 172ms |
| Geneva (Russia TSPU) | ✅ 203ms | ✅ 181ms |
| Geneva (China GFW) | ✅ 157ms | ✅ 184ms |
| Geneva (Iran DPI) | ✅ 176ms | ✅ 188ms |
| Anti-Probe Resistance | ✅ 956ms | ✅ 922ms |
| Protocol Confusion (DNS/TLS) | ✅ 116ms | ✅ 115ms |
| Protocol Confusion (HTTP/TLS) | ✅ 111ms | ✅ 135ms |
| Protocol Confusion (SSH/TLS) | ✅ 112ms | ✅ 127ms |
| Protocol Confusion (SMTP/TLS) | ✅ 123ms | ✅ 127ms |
| Protocol Confusion (Multi-Layer) | ✅ 130ms | ✅ 126ms |
| State Table Exhaustion | ✅ 2226ms | ✅ 2092ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 86ms | ✅ 123ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 115ms | ✅ 165ms |
| HTTP/2 Steganography | ✅ 118ms | ✅ 170ms |
| WebSocket Salamander | ✅ 117ms | ✅ 136ms |
| Traffic Morph (Yandex Video) | ✅ 124ms | ✅ 142ms |
| Traffic Morph (VK Video) | ✅ 115ms | ✅ 136ms |
| Traffic Morph (Baidu Video) | ✅ 119ms | ✅ 169ms |
| Traffic Morph (Aparat Video) | ✅ 117ms | ✅ 155ms |
| Geneva (Russia TSPU) | ✅ 115ms | ✅ 167ms |
| Geneva (China GFW) | ✅ 133ms | ✅ 170ms |
| Geneva (Iran DPI) | ✅ 123ms | ✅ 143ms |
| Anti-Probe Resistance | ✅ 883ms | ✅ 922ms |
| Protocol Confusion (DNS/TLS) | ✅ 91ms | ✅ 101ms |
| Protocol Confusion (HTTP/TLS) | ✅ 82ms | ✅ 100ms |
| Protocol Confusion (SSH/TLS) | ✅ 81ms | ✅ 118ms |
| Protocol Confusion (SMTP/TLS) | ✅ 78ms | ✅ 117ms |
| Protocol Confusion (Multi-Layer) | ✅ 81ms | ✅ 117ms |
| State Table Exhaustion | ✅ 2093ms | ✅ 2095ms |

---
*Generated automatically.*
