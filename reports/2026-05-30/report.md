# TiredVPN Availability Report — 2026-05-30

**Date:** 2026-05-30  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_3 | 98ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_2 | 79ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_4 | 142ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_3 | 98ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 117ms | ✅ 175ms |
| REALITY Protocol | ✅ 200ms | ✅ 199ms |
| HTTP Polling (meek-style) | ✅ 161ms | ✅ 226ms |
| HTTP/2 Steganography | ✅ 135ms | ✅ 226ms |
| WebSocket Salamander | ✅ 156ms | ✅ 224ms |
| Traffic Morph (Yandex Video) | ✅ 136ms | ✅ 180ms |
| Traffic Morph (VK Video) | ✅ 142ms | ✅ 219ms |
| Traffic Morph (Baidu Video) | ✅ 126ms | ✅ 226ms |
| Traffic Morph (Aparat Video) | ✅ 138ms | ✅ 221ms |
| Geneva (Russia TSPU) | ✅ 138ms | ✅ 226ms |
| Geneva (China GFW) | ✅ 128ms | ✅ 226ms |
| Geneva (Iran DPI) | ✅ 126ms | ✅ 181ms |
| Anti-Probe Resistance | ✅ 900ms | ✅ 994ms |
| Protocol Confusion (DNS/TLS) | ✅ 108ms | ✅ 174ms |
| Protocol Confusion (HTTP/TLS) | ✅ 101ms | ✅ 142ms |
| Protocol Confusion (SSH/TLS) | ✅ 111ms | ✅ 145ms |
| Protocol Confusion (SMTP/TLS) | ✅ 98ms | ✅ 177ms |
| Protocol Confusion (Multi-Layer) | ✅ 100ms | ✅ 142ms |
| State Table Exhaustion | ✅ 2086ms | ✅ 2115ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 88ms | ✅ 115ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 117ms | ✅ 173ms |
| HTTP/2 Steganography | ✅ 115ms | ✅ 143ms |
| WebSocket Salamander | ✅ 131ms | ✅ 158ms |
| Traffic Morph (Yandex Video) | ✅ 114ms | ✅ 144ms |
| Traffic Morph (VK Video) | ✅ 127ms | ✅ 136ms |
| Traffic Morph (Baidu Video) | ✅ 119ms | ✅ 175ms |
| Traffic Morph (Aparat Video) | ✅ 118ms | ✅ 143ms |
| Geneva (Russia TSPU) | ✅ 121ms | ✅ 141ms |
| Geneva (China GFW) | ✅ 128ms | ✅ 171ms |
| Geneva (Iran DPI) | ✅ 123ms | ✅ 175ms |
| Anti-Probe Resistance | ✅ 880ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 80ms | ✅ 101ms |
| Protocol Confusion (HTTP/TLS) | ✅ 80ms | ✅ 113ms |
| Protocol Confusion (SSH/TLS) | ✅ 79ms | ✅ 118ms |
| Protocol Confusion (SMTP/TLS) | ✅ 85ms | ✅ 98ms |
| Protocol Confusion (Multi-Layer) | ✅ 81ms | ✅ 115ms |
| State Table Exhaustion | ✅ 2080ms | ❌ — |

---
*Generated automatically.*
