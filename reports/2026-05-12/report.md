# TiredVPN Availability Report — 2026-05-12

**Date:** 2026-05-12  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_2 | 88ms |
| Rostelecom → Hetzner Nuremberg | 19 | 0 | confusion_3 | 78ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_2 | 113ms |
| MegaFon → Hetzner Nuremberg | 19 | 0 | confusion_1 | 102ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 126ms | ✅ 128ms |
| REALITY Protocol | ✅ 215ms | ✅ 222ms |
| HTTP Polling (meek-style) | ✅ 169ms | ✅ 178ms |
| HTTP/2 Steganography | ✅ 177ms | ✅ 170ms |
| WebSocket Salamander | ✅ 171ms | ✅ 185ms |
| Traffic Morph (Yandex Video) | ✅ 143ms | ✅ 173ms |
| Traffic Morph (VK Video) | ✅ 142ms | ✅ 185ms |
| Traffic Morph (Baidu Video) | ✅ 143ms | ✅ 178ms |
| Traffic Morph (Aparat Video) | ✅ 174ms | ✅ 175ms |
| Geneva (Russia TSPU) | ✅ 174ms | ✅ 169ms |
| Geneva (China GFW) | ✅ 175ms | ✅ 151ms |
| Geneva (Iran DPI) | ✅ 169ms | ✅ 185ms |
| Anti-Probe Resistance | ✅ 920ms | ✅ 937ms |
| Protocol Confusion (DNS/TLS) | ✅ 107ms | ✅ 118ms |
| Protocol Confusion (HTTP/TLS) | ✅ 110ms | ✅ 128ms |
| Protocol Confusion (SSH/TLS) | ✅ 88ms | ✅ 113ms |
| Protocol Confusion (SMTP/TLS) | ✅ 110ms | ✅ 117ms |
| Protocol Confusion (Multi-Layer) | ✅ 123ms | ✅ 125ms |
| State Table Exhaustion | ✅ 2090ms | ✅ 2094ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 84ms | ✅ 112ms |
| REALITY Protocol | ✅ 176ms | ✅ 200ms |
| HTTP Polling (meek-style) | ✅ 134ms | ✅ 166ms |
| HTTP/2 Steganography | ✅ 136ms | ✅ 175ms |
| WebSocket Salamander | ✅ 126ms | ✅ 167ms |
| Traffic Morph (Yandex Video) | ✅ 118ms | ✅ 173ms |
| Traffic Morph (VK Video) | ✅ 134ms | ✅ 175ms |
| Traffic Morph (Baidu Video) | ✅ 128ms | ✅ 175ms |
| Traffic Morph (Aparat Video) | ✅ 121ms | ✅ 140ms |
| Geneva (Russia TSPU) | ✅ 160ms | ✅ 167ms |
| Geneva (China GFW) | ✅ 121ms | ✅ 167ms |
| Geneva (Iran DPI) | ✅ 136ms | ✅ 169ms |
| Anti-Probe Resistance | ✅ 881ms | ✅ 930ms |
| Protocol Confusion (DNS/TLS) | ✅ 79ms | ✅ 112ms |
| Protocol Confusion (HTTP/TLS) | ✅ 85ms | ✅ 102ms |
| Protocol Confusion (SSH/TLS) | ✅ 79ms | ✅ 109ms |
| Protocol Confusion (SMTP/TLS) | ✅ 78ms | ✅ 109ms |
| Protocol Confusion (Multi-Layer) | ✅ 85ms | ✅ 110ms |
| State Table Exhaustion | ✅ 2081ms | ✅ 2094ms |

---
*Generated automatically.*
