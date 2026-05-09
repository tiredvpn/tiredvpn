# TiredVPN Availability Report — 2026-05-09

**Date:** 2026-05-09  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_1 | 130ms |
| Rostelecom → Hetzner Nuremberg | 19 | 0 | confusion_2 | 82ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_1 | 238ms |
| MegaFon → Hetzner Nuremberg | 19 | 0 | confusion_3 | 103ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 146ms | ✅ 245ms |
| REALITY Protocol | ✅ 234ms | ✅ 443ms |
| HTTP Polling (meek-style) | ✅ 178ms | ✅ 328ms |
| HTTP/2 Steganography | ✅ 175ms | ✅ 327ms |
| WebSocket Salamander | ✅ 166ms | ✅ 327ms |
| Traffic Morph (Yandex Video) | ✅ 165ms | ✅ 327ms |
| Traffic Morph (VK Video) | ✅ 166ms | ✅ 328ms |
| Traffic Morph (Baidu Video) | ✅ 161ms | ✅ 328ms |
| Traffic Morph (Aparat Video) | ✅ 172ms | ✅ 329ms |
| Geneva (Russia TSPU) | ✅ 197ms | ✅ 329ms |
| Geneva (China GFW) | ✅ 193ms | ✅ 328ms |
| Geneva (Iran DPI) | ✅ 177ms | ✅ 310ms |
| Anti-Probe Resistance | ✅ 931ms | ✅ 1049ms |
| Protocol Confusion (DNS/TLS) | ✅ 144ms | ✅ 243ms |
| Protocol Confusion (HTTP/TLS) | ✅ 130ms | ✅ 238ms |
| Protocol Confusion (SSH/TLS) | ✅ 133ms | ✅ 247ms |
| Protocol Confusion (SMTP/TLS) | ✅ 148ms | ✅ 247ms |
| Protocol Confusion (Multi-Layer) | ✅ 134ms | ✅ 247ms |
| State Table Exhaustion | ✅ 2097ms | ✅ 2157ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 98ms | ✅ 124ms |
| REALITY Protocol | ✅ 190ms | ✅ 200ms |
| HTTP Polling (meek-style) | ✅ 127ms | ✅ 173ms |
| HTTP/2 Steganography | ✅ 122ms | ✅ 171ms |
| WebSocket Salamander | ✅ 131ms | ✅ 169ms |
| Traffic Morph (Yandex Video) | ✅ 130ms | ✅ 167ms |
| Traffic Morph (VK Video) | ✅ 124ms | ✅ 146ms |
| Traffic Morph (Baidu Video) | ✅ 121ms | ✅ 142ms |
| Traffic Morph (Aparat Video) | ✅ 132ms | ✅ 162ms |
| Geneva (Russia TSPU) | ✅ 154ms | ✅ 166ms |
| Geneva (China GFW) | ✅ 136ms | ✅ 140ms |
| Geneva (Iran DPI) | ✅ 114ms | ✅ 143ms |
| Anti-Probe Resistance | ✅ 879ms | ✅ 913ms |
| Protocol Confusion (DNS/TLS) | ✅ 94ms | ✅ 112ms |
| Protocol Confusion (HTTP/TLS) | ✅ 92ms | ✅ 124ms |
| Protocol Confusion (SSH/TLS) | ✅ 82ms | ✅ 109ms |
| Protocol Confusion (SMTP/TLS) | ✅ 87ms | ✅ 103ms |
| Protocol Confusion (Multi-Layer) | ✅ 93ms | ✅ 124ms |
| State Table Exhaustion | ✅ 2079ms | ✅ 2105ms |

---
*Generated automatically.*
