# TiredVPN Availability Report — 2026-05-08

**Date:** 2026-05-08  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_2 | 85ms |
| Rostelecom → Hetzner Nuremberg | 19 | 0 | confusion_1 | 84ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_2 | 121ms |
| MegaFon → Hetzner Nuremberg | 19 | 0 | confusion_3 | 115ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 111ms | ✅ 134ms |
| REALITY Protocol | ✅ 189ms | ✅ 225ms |
| HTTP Polling (meek-style) | ✅ 147ms | ✅ 176ms |
| HTTP/2 Steganography | ✅ 132ms | ✅ 185ms |
| WebSocket Salamander | ✅ 139ms | ✅ 170ms |
| Traffic Morph (Yandex Video) | ✅ 125ms | ✅ 185ms |
| Traffic Morph (VK Video) | ✅ 141ms | ✅ 172ms |
| Traffic Morph (Baidu Video) | ✅ 143ms | ✅ 172ms |
| Traffic Morph (Aparat Video) | ✅ 124ms | ✅ 149ms |
| Geneva (Russia TSPU) | ✅ 162ms | ✅ 173ms |
| Geneva (China GFW) | ✅ 143ms | ✅ 167ms |
| Geneva (Iran DPI) | ✅ 127ms | ✅ 181ms |
| Anti-Probe Resistance | ✅ 885ms | ✅ 955ms |
| Protocol Confusion (DNS/TLS) | ✅ 108ms | ✅ 130ms |
| Protocol Confusion (HTTP/TLS) | ✅ 100ms | ✅ 123ms |
| Protocol Confusion (SSH/TLS) | ✅ 85ms | ✅ 121ms |
| Protocol Confusion (SMTP/TLS) | ✅ 109ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 96ms | ✅ 123ms |
| State Table Exhaustion | ✅ 2098ms | ✅ 2114ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 90ms | ✅ 124ms |
| REALITY Protocol | ✅ 177ms | ✅ 194ms |
| HTTP Polling (meek-style) | ✅ 137ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 117ms | ✅ 167ms |
| WebSocket Salamander | ✅ 125ms | ✅ 164ms |
| Traffic Morph (Yandex Video) | ✅ 112ms | ✅ 138ms |
| Traffic Morph (VK Video) | ✅ 131ms | ✅ 138ms |
| Traffic Morph (Baidu Video) | ✅ 117ms | ✅ 153ms |
| Traffic Morph (Aparat Video) | ✅ 123ms | ✅ 140ms |
| Geneva (Russia TSPU) | ✅ 112ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 136ms | ✅ 164ms |
| Geneva (Iran DPI) | ✅ 124ms | ✅ 172ms |
| Anti-Probe Resistance | ✅ 895ms | ✅ 920ms |
| Protocol Confusion (DNS/TLS) | ✅ 91ms | ✅ 115ms |
| Protocol Confusion (HTTP/TLS) | ✅ 84ms | ✅ 124ms |
| Protocol Confusion (SSH/TLS) | ✅ 85ms | ✅ 123ms |
| Protocol Confusion (SMTP/TLS) | ✅ 88ms | ✅ 115ms |
| Protocol Confusion (Multi-Layer) | ✅ 85ms | ✅ 124ms |
| State Table Exhaustion | ✅ 2076ms | ✅ 2105ms |

---
*Generated automatically.*
