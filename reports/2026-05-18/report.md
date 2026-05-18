# TiredVPN Availability Report — 2026-05-18

**Date:** 2026-05-18  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | quic_salamander | 119ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_0 | 85ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 126ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_1 | 94ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 119ms | ✅ 132ms |
| REALITY Protocol | ✅ 230ms | ✅ 227ms |
| HTTP Polling (meek-style) | ✅ 189ms | ✅ 156ms |
| HTTP/2 Steganography | ✅ 169ms | ✅ 174ms |
| WebSocket Salamander | ✅ 179ms | ✅ 164ms |
| Traffic Morph (Yandex Video) | ✅ 143ms | ✅ 180ms |
| Traffic Morph (VK Video) | ✅ 155ms | ✅ 168ms |
| Traffic Morph (Baidu Video) | ✅ 155ms | ✅ 180ms |
| Traffic Morph (Aparat Video) | ✅ 147ms | ✅ 169ms |
| Geneva (Russia TSPU) | ✅ 160ms | ✅ 171ms |
| Geneva (China GFW) | ✅ 178ms | ✅ 177ms |
| Geneva (Iran DPI) | ✅ 182ms | ✅ 171ms |
| Anti-Probe Resistance | ✅ 943ms | ✅ 941ms |
| Protocol Confusion (DNS/TLS) | ✅ 133ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 122ms | ✅ 127ms |
| Protocol Confusion (SSH/TLS) | ✅ 123ms | ✅ 127ms |
| Protocol Confusion (SMTP/TLS) | ✅ 139ms | ✅ 130ms |
| Protocol Confusion (Multi-Layer) | ✅ 120ms | ✅ 131ms |
| State Table Exhaustion | ✅ 2084ms | ✅ 2104ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 97ms | ✅ 108ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 126ms | ✅ 139ms |
| HTTP/2 Steganography | ✅ 123ms | ✅ 146ms |
| WebSocket Salamander | ✅ 125ms | ✅ 151ms |
| Traffic Morph (Yandex Video) | ✅ 125ms | ✅ 131ms |
| Traffic Morph (VK Video) | ✅ 129ms | ✅ 133ms |
| Traffic Morph (Baidu Video) | ✅ 138ms | ✅ 143ms |
| Traffic Morph (Aparat Video) | ✅ 136ms | ✅ 130ms |
| Geneva (Russia TSPU) | ✅ 141ms | ✅ 137ms |
| Geneva (China GFW) | ✅ 165ms | ✅ 139ms |
| Geneva (Iran DPI) | ✅ 134ms | ✅ 147ms |
| Anti-Probe Resistance | ✅ 885ms | ✅ 899ms |
| Protocol Confusion (DNS/TLS) | ✅ 85ms | ✅ 102ms |
| Protocol Confusion (HTTP/TLS) | ✅ 86ms | ✅ 94ms |
| Protocol Confusion (SSH/TLS) | ✅ 95ms | ✅ 105ms |
| Protocol Confusion (SMTP/TLS) | ✅ 91ms | ✅ 112ms |
| Protocol Confusion (Multi-Layer) | ✅ 92ms | ✅ 106ms |
| State Table Exhaustion | ✅ 2083ms | ✅ 2096ms |

---
*Generated automatically.*
