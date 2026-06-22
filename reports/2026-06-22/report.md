# TiredVPN Availability Report — 2026-06-22

**Date:** 2026-06-22  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_3 | 116ms |
| Rostelecom → Hetzner Nuremberg | 16 | 3 | confusion_2 | 88ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 185ms |
| WebSocket Salamander | ✅ 183ms |
| Traffic Morph (Yandex Video) | ✅ 180ms |
| Traffic Morph (VK Video) | ✅ 184ms |
| Traffic Morph (Baidu Video) | ✅ 149ms |
| Traffic Morph (Aparat Video) | ✅ 142ms |
| Geneva (Russia TSPU) | ✅ 216ms |
| Geneva (China GFW) | ✅ 209ms |
| Geneva (Iran DPI) | ✅ 244ms |
| Anti-Probe Resistance | ✅ 961ms |
| Protocol Confusion (DNS/TLS) | ✅ 128ms |
| Protocol Confusion (HTTP/TLS) | ✅ 123ms |
| Protocol Confusion (SSH/TLS) | ✅ 132ms |
| Protocol Confusion (SMTP/TLS) | ✅ 116ms |
| Protocol Confusion (Multi-Layer) | ✅ 187ms |
| State Table Exhaustion | ✅ 2109ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 141ms |
| WebSocket Salamander | ✅ 136ms |
| Traffic Morph (Yandex Video) | ✅ 145ms |
| Traffic Morph (VK Video) | ✅ 130ms |
| Traffic Morph (Baidu Video) | ✅ 129ms |
| Traffic Morph (Aparat Video) | ✅ 130ms |
| Geneva (Russia TSPU) | ✅ 181ms |
| Geneva (China GFW) | ✅ 142ms |
| Geneva (Iran DPI) | ✅ 140ms |
| Anti-Probe Resistance | ✅ 883ms |
| Protocol Confusion (DNS/TLS) | ✅ 96ms |
| Protocol Confusion (HTTP/TLS) | ✅ 89ms |
| Protocol Confusion (SSH/TLS) | ✅ 88ms |
| Protocol Confusion (SMTP/TLS) | ✅ 100ms |
| Protocol Confusion (Multi-Layer) | ✅ 93ms |
| State Table Exhaustion | ✅ 2093ms |

---
*Generated automatically.*
