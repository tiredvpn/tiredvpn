# TiredVPN Availability Report — 2026-05-26

**Date:** 2026-05-26  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_3 | 95ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 77ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_3 | 103ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_2 | 108ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 124ms | ✅ 139ms |
| REALITY Protocol | ✅ 208ms | ✅ 231ms |
| HTTP Polling (meek-style) | ✅ 173ms | ✅ 178ms |
| HTTP/2 Steganography | ✅ 166ms | ✅ 181ms |
| WebSocket Salamander | ✅ 136ms | ✅ 170ms |
| Traffic Morph (Yandex Video) | ✅ 126ms | ✅ 164ms |
| Traffic Morph (VK Video) | ✅ 143ms | ✅ 176ms |
| Traffic Morph (Baidu Video) | ✅ 124ms | ✅ 174ms |
| Traffic Morph (Aparat Video) | ✅ 145ms | ✅ 169ms |
| Geneva (Russia TSPU) | ✅ 164ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 173ms | ✅ 177ms |
| Geneva (Iran DPI) | ✅ 143ms | ✅ 170ms |
| Anti-Probe Resistance | ✅ 908ms | ✅ 940ms |
| Protocol Confusion (DNS/TLS) | ✅ 120ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 115ms | ✅ 118ms |
| Protocol Confusion (SSH/TLS) | ✅ 113ms | ✅ 136ms |
| Protocol Confusion (SMTP/TLS) | ✅ 95ms | ✅ 103ms |
| Protocol Confusion (Multi-Layer) | ✅ 120ms | ✅ 125ms |
| State Table Exhaustion | ✅ 2085ms | ✅ 2107ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 84ms | ✅ 119ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 128ms | ✅ 168ms |
| HTTP/2 Steganography | ✅ 125ms | ✅ 141ms |
| WebSocket Salamander | ✅ 133ms | ✅ 145ms |
| Traffic Morph (Yandex Video) | ✅ 126ms | ✅ 172ms |
| Traffic Morph (VK Video) | ✅ 116ms | ✅ 172ms |
| Traffic Morph (Baidu Video) | ✅ 133ms | ✅ 159ms |
| Traffic Morph (Aparat Video) | ✅ 131ms | ✅ 146ms |
| Geneva (Russia TSPU) | ✅ 116ms | ✅ 140ms |
| Geneva (China GFW) | ✅ 118ms | ✅ 140ms |
| Geneva (Iran DPI) | ✅ 124ms | ✅ 168ms |
| Anti-Probe Resistance | ✅ 872ms | ✅ 917ms |
| Protocol Confusion (DNS/TLS) | ✅ 78ms | ✅ 118ms |
| Protocol Confusion (HTTP/TLS) | ✅ 90ms | ✅ 117ms |
| Protocol Confusion (SSH/TLS) | ✅ 91ms | ✅ 108ms |
| Protocol Confusion (SMTP/TLS) | ✅ 77ms | ✅ 119ms |
| Protocol Confusion (Multi-Layer) | ✅ 82ms | ✅ 109ms |
| State Table Exhaustion | ✅ 2092ms | ❌ — |

---
*Generated automatically.*
