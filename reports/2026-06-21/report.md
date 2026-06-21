# TiredVPN Availability Report — 2026-06-21

**Date:** 2026-06-21  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_0 | 112ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_3 | 89ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 163ms |
| WebSocket Salamander | ✅ 188ms |
| Traffic Morph (Yandex Video) | ✅ 152ms |
| Traffic Morph (VK Video) | ✅ 149ms |
| Traffic Morph (Baidu Video) | ✅ 149ms |
| Traffic Morph (Aparat Video) | ✅ 148ms |
| Geneva (Russia TSPU) | ✅ 213ms |
| Geneva (China GFW) | ✅ 188ms |
| Geneva (Iran DPI) | ✅ 163ms |
| Anti-Probe Resistance | ✅ 939ms |
| Protocol Confusion (DNS/TLS) | ✅ 112ms |
| Protocol Confusion (HTTP/TLS) | ✅ 128ms |
| Protocol Confusion (SSH/TLS) | ✅ 149ms |
| Protocol Confusion (SMTP/TLS) | ✅ 126ms |
| Protocol Confusion (Multi-Layer) | ✅ 130ms |
| State Table Exhaustion | ✅ 2101ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 132ms |
| WebSocket Salamander | ✅ 130ms |
| Traffic Morph (Yandex Video) | ✅ 144ms |
| Traffic Morph (VK Video) | ✅ 128ms |
| Traffic Morph (Baidu Video) | ✅ 123ms |
| Traffic Morph (Aparat Video) | ✅ 124ms |
| Geneva (Russia TSPU) | ✅ 186ms |
| Geneva (China GFW) | ✅ 149ms |
| Geneva (Iran DPI) | ✅ 131ms |
| Anti-Probe Resistance | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 94ms |
| Protocol Confusion (HTTP/TLS) | ✅ 101ms |
| Protocol Confusion (SSH/TLS) | ✅ 91ms |
| Protocol Confusion (SMTP/TLS) | ✅ 89ms |
| Protocol Confusion (Multi-Layer) | ✅ 104ms |
| State Table Exhaustion | ✅ 2095ms |

---
*Generated automatically.*
