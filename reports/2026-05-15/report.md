# TiredVPN Availability Report — 2026-05-15

**Date:** 2026-05-15  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_4 | 172ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_4 | 82ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 124ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_2 | 107ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 177ms | ✅ 136ms |
| REALITY Protocol | ✅ 302ms | ✅ 222ms |
| HTTP Polling (meek-style) | ✅ 244ms | ✅ 183ms |
| HTTP/2 Steganography | ✅ 274ms | ✅ 185ms |
| WebSocket Salamander | ✅ 273ms | ✅ 175ms |
| Traffic Morph (Yandex Video) | ✅ 278ms | ✅ 143ms |
| Traffic Morph (VK Video) | ✅ 279ms | ✅ 177ms |
| Traffic Morph (Baidu Video) | ✅ 276ms | ✅ 148ms |
| Traffic Morph (Aparat Video) | ✅ 272ms | ✅ 147ms |
| Geneva (Russia TSPU) | ✅ 322ms | ✅ 177ms |
| Geneva (China GFW) | ✅ 312ms | ✅ 173ms |
| Geneva (Iran DPI) | ✅ 243ms | ✅ 173ms |
| Anti-Probe Resistance | ✅ 992ms | ✅ 929ms |
| Protocol Confusion (DNS/TLS) | ✅ 175ms | ✅ 124ms |
| Protocol Confusion (HTTP/TLS) | ✅ 184ms | ✅ 134ms |
| Protocol Confusion (SSH/TLS) | ✅ 180ms | ✅ 135ms |
| Protocol Confusion (SMTP/TLS) | ✅ 174ms | ✅ 133ms |
| Protocol Confusion (Multi-Layer) | ✅ 172ms | ✅ 131ms |
| State Table Exhaustion | ✅ 2146ms | ✅ 2102ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 90ms | ✅ 125ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 139ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 128ms | ✅ 170ms |
| WebSocket Salamander | ✅ 117ms | ✅ 154ms |
| Traffic Morph (Yandex Video) | ✅ 125ms | ✅ 168ms |
| Traffic Morph (VK Video) | ✅ 116ms | ✅ 168ms |
| Traffic Morph (Baidu Video) | ✅ 124ms | ✅ 168ms |
| Traffic Morph (Aparat Video) | ✅ 135ms | ✅ 148ms |
| Geneva (Russia TSPU) | ✅ 133ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 128ms | ✅ 170ms |
| Geneva (Iran DPI) | ✅ 125ms | ✅ 176ms |
| Anti-Probe Resistance | ✅ 875ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 86ms | ✅ 113ms |
| Protocol Confusion (HTTP/TLS) | ✅ 89ms | ✅ 122ms |
| Protocol Confusion (SSH/TLS) | ✅ 83ms | ✅ 107ms |
| Protocol Confusion (SMTP/TLS) | ✅ 92ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 82ms | ✅ 125ms |
| State Table Exhaustion | ✅ 2080ms | ✅ 2099ms |

---
*Generated automatically.*
