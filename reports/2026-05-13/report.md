# TiredVPN Availability Report — 2026-05-13

**Date:** 2026-05-13  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_2 | 92ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_2 | 81ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_2 | 118ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_4 | 109ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 102ms | ✅ 141ms |
| REALITY Protocol | ✅ 199ms | ✅ 226ms |
| HTTP Polling (meek-style) | ✅ 158ms | ✅ 190ms |
| HTTP/2 Steganography | ✅ 126ms | ✅ 187ms |
| WebSocket Salamander | ✅ 131ms | ✅ 166ms |
| Traffic Morph (Yandex Video) | ✅ 132ms | ✅ 180ms |
| Traffic Morph (VK Video) | ✅ 136ms | ✅ 174ms |
| Traffic Morph (Baidu Video) | ✅ 131ms | ✅ 174ms |
| Traffic Morph (Aparat Video) | ✅ 129ms | ✅ 149ms |
| Geneva (Russia TSPU) | ✅ 155ms | ✅ 189ms |
| Geneva (China GFW) | ✅ 134ms | ✅ 175ms |
| Geneva (Iran DPI) | ✅ 132ms | ✅ 177ms |
| Anti-Probe Resistance | ✅ 886ms | ✅ 922ms |
| Protocol Confusion (DNS/TLS) | ✅ 110ms | ✅ 137ms |
| Protocol Confusion (HTTP/TLS) | ✅ 106ms | ✅ 142ms |
| Protocol Confusion (SSH/TLS) | ✅ 92ms | ✅ 118ms |
| Protocol Confusion (SMTP/TLS) | ✅ 103ms | ✅ 129ms |
| Protocol Confusion (Multi-Layer) | ✅ 107ms | ✅ 126ms |
| State Table Exhaustion | ✅ 2091ms | ✅ 2113ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 84ms | ✅ 109ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 125ms | ✅ 170ms |
| HTTP/2 Steganography | ✅ 130ms | ✅ 170ms |
| WebSocket Salamander | ✅ 131ms | ✅ 170ms |
| Traffic Morph (Yandex Video) | ✅ 136ms | ✅ 141ms |
| Traffic Morph (VK Video) | ✅ 122ms | ✅ 171ms |
| Traffic Morph (Baidu Video) | ✅ 121ms | ✅ 170ms |
| Traffic Morph (Aparat Video) | ✅ 124ms | ✅ 166ms |
| Geneva (Russia TSPU) | ✅ 126ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 121ms | ✅ 170ms |
| Geneva (Iran DPI) | ✅ 128ms | ✅ 167ms |
| Anti-Probe Resistance | ✅ 879ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 83ms | ✅ 109ms |
| Protocol Confusion (HTTP/TLS) | ✅ 87ms | ✅ 115ms |
| Protocol Confusion (SSH/TLS) | ✅ 81ms | ✅ 114ms |
| Protocol Confusion (SMTP/TLS) | ✅ 90ms | ✅ 123ms |
| Protocol Confusion (Multi-Layer) | ✅ 82ms | ✅ 109ms |
| State Table Exhaustion | ✅ 2083ms | ✅ 2113ms |

---
*Generated automatically.*
