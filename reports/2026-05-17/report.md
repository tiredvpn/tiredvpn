# TiredVPN Availability Report — 2026-05-17

**Date:** 2026-05-17  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_1 | 91ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 76ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_2 | 110ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_1 | 117ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 116ms | ✅ 127ms |
| REALITY Protocol | ✅ 205ms | ✅ 221ms |
| HTTP Polling (meek-style) | ✅ 150ms | ✅ 170ms |
| HTTP/2 Steganography | ✅ 158ms | ✅ 181ms |
| WebSocket Salamander | ✅ 135ms | ✅ 172ms |
| Traffic Morph (Yandex Video) | ✅ 135ms | ✅ 174ms |
| Traffic Morph (VK Video) | ✅ 124ms | ✅ 178ms |
| Traffic Morph (Baidu Video) | ✅ 132ms | ✅ 166ms |
| Traffic Morph (Aparat Video) | ✅ 128ms | ✅ 167ms |
| Geneva (Russia TSPU) | ✅ 142ms | ✅ 181ms |
| Geneva (China GFW) | ✅ 158ms | ✅ 180ms |
| Geneva (Iran DPI) | ✅ 149ms | ✅ 177ms |
| Anti-Probe Resistance | ✅ 910ms | ✅ 923ms |
| Protocol Confusion (DNS/TLS) | ✅ 112ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 91ms | ✅ 125ms |
| Protocol Confusion (SSH/TLS) | ✅ 102ms | ✅ 110ms |
| Protocol Confusion (SMTP/TLS) | ✅ 93ms | ✅ 126ms |
| Protocol Confusion (Multi-Layer) | ✅ 106ms | ✅ 128ms |
| State Table Exhaustion | ✅ 2183ms | ✅ 2104ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 92ms | ✅ 123ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 121ms | ✅ 167ms |
| HTTP/2 Steganography | ✅ 118ms | ✅ 170ms |
| WebSocket Salamander | ✅ 122ms | ✅ 165ms |
| Traffic Morph (Yandex Video) | ✅ 124ms | ✅ 160ms |
| Traffic Morph (VK Video) | ✅ 136ms | ✅ 165ms |
| Traffic Morph (Baidu Video) | ✅ 119ms | ✅ 176ms |
| Traffic Morph (Aparat Video) | ✅ 130ms | ✅ 177ms |
| Geneva (Russia TSPU) | ✅ 124ms | ✅ 163ms |
| Geneva (China GFW) | ✅ 123ms | ✅ 164ms |
| Geneva (Iran DPI) | ✅ 118ms | ✅ 172ms |
| Anti-Probe Resistance | ✅ 885ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 84ms | ✅ 124ms |
| Protocol Confusion (HTTP/TLS) | ✅ 83ms | ✅ 117ms |
| Protocol Confusion (SSH/TLS) | ✅ 80ms | ✅ 124ms |
| Protocol Confusion (SMTP/TLS) | ✅ 76ms | ✅ 124ms |
| Protocol Confusion (Multi-Layer) | ✅ 85ms | ✅ 123ms |
| State Table Exhaustion | ✅ 2085ms | ✅ 2103ms |

---
*Generated automatically.*
