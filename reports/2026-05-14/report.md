# TiredVPN Availability Report — 2026-05-14

**Date:** 2026-05-14  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_0 | 101ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 76ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 117ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_2 | 104ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 114ms | ✅ 161ms |
| REALITY Protocol | ✅ 240ms | ✅ 252ms |
| HTTP Polling (meek-style) | ✅ 164ms | ✅ 230ms |
| HTTP/2 Steganography | ✅ 150ms | ✅ 224ms |
| WebSocket Salamander | ✅ 203ms | ✅ 176ms |
| Traffic Morph (Yandex Video) | ✅ 151ms | ✅ 172ms |
| Traffic Morph (VK Video) | ✅ 151ms | ✅ 208ms |
| Traffic Morph (Baidu Video) | ✅ 151ms | ✅ 213ms |
| Traffic Morph (Aparat Video) | ✅ 150ms | ✅ 178ms |
| Geneva (Russia TSPU) | ✅ 185ms | ✅ 181ms |
| Geneva (China GFW) | ✅ 154ms | ✅ 182ms |
| Geneva (Iran DPI) | ✅ 175ms | ✅ 223ms |
| Anti-Probe Resistance | ✅ 927ms | ✅ 965ms |
| Protocol Confusion (DNS/TLS) | ✅ 101ms | ✅ 117ms |
| Protocol Confusion (HTTP/TLS) | ✅ 115ms | ✅ 123ms |
| Protocol Confusion (SSH/TLS) | ✅ 107ms | ✅ 126ms |
| Protocol Confusion (SMTP/TLS) | ✅ 135ms | ✅ 122ms |
| Protocol Confusion (Multi-Layer) | ✅ 130ms | ✅ 147ms |
| State Table Exhaustion | ✅ 2095ms | ✅ 2100ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 97ms | ✅ 125ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 127ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 125ms | ✅ 136ms |
| WebSocket Salamander | ✅ 124ms | ✅ 149ms |
| Traffic Morph (Yandex Video) | ✅ 119ms | ✅ 142ms |
| Traffic Morph (VK Video) | ✅ 123ms | ✅ 152ms |
| Traffic Morph (Baidu Video) | ✅ 128ms | ✅ 167ms |
| Traffic Morph (Aparat Video) | ✅ 117ms | ✅ 143ms |
| Geneva (Russia TSPU) | ✅ 124ms | ✅ 165ms |
| Geneva (China GFW) | ✅ 152ms | ✅ 163ms |
| Geneva (Iran DPI) | ✅ 132ms | ✅ 151ms |
| Anti-Probe Resistance | ✅ 883ms | ✅ 906ms |
| Protocol Confusion (DNS/TLS) | ✅ 93ms | ✅ 104ms |
| Protocol Confusion (HTTP/TLS) | ✅ 92ms | ✅ 115ms |
| Protocol Confusion (SSH/TLS) | ✅ 84ms | ✅ 104ms |
| Protocol Confusion (SMTP/TLS) | ✅ 76ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 91ms | ✅ 115ms |
| State Table Exhaustion | ✅ 2092ms | ✅ 2099ms |

---
*Generated automatically.*
