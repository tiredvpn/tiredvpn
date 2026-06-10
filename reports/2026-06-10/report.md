# TiredVPN Availability Report — 2026-06-10

**Date:** 2026-06-10  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_0 | 99ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | confusion_4 | 84ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_1 | 103ms |
| MegaFon → Hetzner Nuremberg | 12 | 7 | confusion_1 | 99ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 125ms | ✅ 133ms |
| REALITY Protocol | ✅ 232ms | ✅ 216ms |
| HTTP Polling (meek-style) | ✅ 161ms | ✅ 174ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 154ms | ✅ 175ms |
| Traffic Morph (Yandex Video) | ✅ 153ms | ✅ 151ms |
| Traffic Morph (VK Video) | ✅ 142ms | ✅ 170ms |
| Traffic Morph (Baidu Video) | ✅ 142ms | ✅ 167ms |
| Traffic Morph (Aparat Video) | ✅ 158ms | ✅ 168ms |
| Geneva (Russia TSPU) | ✅ 184ms | ✅ 175ms |
| Geneva (China GFW) | ✅ 183ms | ✅ 177ms |
| Geneva (Iran DPI) | ✅ 154ms | ✅ 171ms |
| Anti-Probe Resistance | ✅ 918ms | ✅ 934ms |
| Protocol Confusion (DNS/TLS) | ✅ 99ms | ✅ 132ms |
| Protocol Confusion (HTTP/TLS) | ✅ 111ms | ✅ 103ms |
| Protocol Confusion (SSH/TLS) | ✅ 116ms | ✅ 118ms |
| Protocol Confusion (SMTP/TLS) | ✅ 115ms | ✅ 114ms |
| Protocol Confusion (Multi-Layer) | ✅ 117ms | ✅ 130ms |
| State Table Exhaustion | ✅ 2089ms | ✅ 2105ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 88ms | ✅ 119ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 129ms | ✅ 168ms |
| HTTP/2 Steganography | ✅ 124ms | ✅ 145ms |
| WebSocket Salamander | ✅ 121ms | ✅ 138ms |
| Traffic Morph (Yandex Video) | ✅ 121ms | ❌ — |
| Traffic Morph (VK Video) | ✅ 119ms | ❌ — |
| Traffic Morph (Baidu Video) | ✅ 131ms | ❌ — |
| Traffic Morph (Aparat Video) | ✅ 133ms | ❌ — |
| Geneva (Russia TSPU) | ✅ 166ms | ✅ 164ms |
| Geneva (China GFW) | ✅ 171ms | ✅ 163ms |
| Geneva (Iran DPI) | ✅ 126ms | ✅ 165ms |
| Anti-Probe Resistance | ❌ — | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 88ms | ✅ 119ms |
| Protocol Confusion (HTTP/TLS) | ✅ 85ms | ✅ 99ms |
| Protocol Confusion (SSH/TLS) | ✅ 86ms | ✅ 106ms |
| Protocol Confusion (SMTP/TLS) | ✅ 94ms | ✅ 100ms |
| Protocol Confusion (Multi-Layer) | ✅ 84ms | ✅ 123ms |
| State Table Exhaustion | ✅ 2091ms | ❌ — |

---
*Generated automatically.*
