# TiredVPN Availability Report — 2026-05-23

**Date:** 2026-05-23  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_0 | 105ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_0 | 82ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_2 | 186ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_3 | 101ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 123ms | ✅ 222ms |
| REALITY Protocol | ✅ 197ms | ✅ 360ms |
| HTTP Polling (meek-style) | ✅ 146ms | ✅ 263ms |
| HTTP/2 Steganography | ✅ 163ms | ✅ 226ms |
| WebSocket Salamander | ✅ 143ms | ✅ 251ms |
| Traffic Morph (Yandex Video) | ✅ 143ms | ✅ 244ms |
| Traffic Morph (VK Video) | ✅ 140ms | ✅ 252ms |
| Traffic Morph (Baidu Video) | ✅ 129ms | ✅ 251ms |
| Traffic Morph (Aparat Video) | ✅ 125ms | ✅ 245ms |
| Geneva (Russia TSPU) | ✅ 137ms | ✅ 256ms |
| Geneva (China GFW) | ✅ 138ms | ✅ 294ms |
| Geneva (Iran DPI) | ✅ 173ms | ✅ 254ms |
| Anti-Probe Resistance | ✅ 928ms | ✅ 1001ms |
| Protocol Confusion (DNS/TLS) | ✅ 105ms | ✅ 222ms |
| Protocol Confusion (HTTP/TLS) | ✅ 118ms | ✅ 223ms |
| Protocol Confusion (SSH/TLS) | ✅ 123ms | ✅ 186ms |
| Protocol Confusion (SMTP/TLS) | ✅ 106ms | ✅ 221ms |
| Protocol Confusion (Multi-Layer) | ✅ 107ms | ✅ 201ms |
| State Table Exhaustion | ✅ 2094ms | ✅ 2097ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 94ms | ✅ 110ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 130ms | ✅ 164ms |
| HTTP/2 Steganography | ✅ 128ms | ✅ 174ms |
| WebSocket Salamander | ✅ 128ms | ✅ 174ms |
| Traffic Morph (Yandex Video) | ✅ 122ms | ✅ 144ms |
| Traffic Morph (VK Video) | ✅ 129ms | ✅ 171ms |
| Traffic Morph (Baidu Video) | ✅ 132ms | ✅ 169ms |
| Traffic Morph (Aparat Video) | ✅ 135ms | ✅ 170ms |
| Geneva (Russia TSPU) | ✅ 121ms | ✅ 169ms |
| Geneva (China GFW) | ✅ 118ms | ✅ 165ms |
| Geneva (Iran DPI) | ✅ 134ms | ✅ 168ms |
| Anti-Probe Resistance | ✅ 895ms | ✅ 935ms |
| Protocol Confusion (DNS/TLS) | ✅ 82ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 90ms | ✅ 102ms |
| Protocol Confusion (SSH/TLS) | ✅ 91ms | ✅ 123ms |
| Protocol Confusion (SMTP/TLS) | ✅ 91ms | ✅ 101ms |
| Protocol Confusion (Multi-Layer) | ✅ 92ms | ✅ 127ms |
| State Table Exhaustion | ✅ 2081ms | ✅ 2112ms |

---
*Generated automatically.*
