# TiredVPN Availability Report — 2026-06-20

**Date:** 2026-06-20  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_3 | 101ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_0 | 87ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 182ms |
| WebSocket Salamander | ✅ 182ms |
| Traffic Morph (Yandex Video) | ✅ 166ms |
| Traffic Morph (VK Video) | ✅ 165ms |
| Traffic Morph (Baidu Video) | ✅ 165ms |
| Traffic Morph (Aparat Video) | ✅ 164ms |
| Geneva (Russia TSPU) | ✅ 228ms |
| Geneva (China GFW) | ✅ 206ms |
| Geneva (Iran DPI) | ✅ 181ms |
| Anti-Probe Resistance | ✅ 948ms |
| Protocol Confusion (DNS/TLS) | ✅ 139ms |
| Protocol Confusion (HTTP/TLS) | ✅ 115ms |
| Protocol Confusion (SSH/TLS) | ✅ 145ms |
| Protocol Confusion (SMTP/TLS) | ✅ 101ms |
| Protocol Confusion (Multi-Layer) | ✅ 132ms |
| State Table Exhaustion | ✅ 2131ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 137ms |
| WebSocket Salamander | ✅ 141ms |
| Traffic Morph (Yandex Video) | ✅ 124ms |
| Traffic Morph (VK Video) | ✅ 126ms |
| Traffic Morph (Baidu Video) | ✅ 127ms |
| Traffic Morph (Aparat Video) | ✅ 123ms |
| Geneva (Russia TSPU) | ✅ 135ms |
| Geneva (China GFW) | ✅ 136ms |
| Geneva (Iran DPI) | ✅ 138ms |
| Anti-Probe Resistance | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 87ms |
| Protocol Confusion (HTTP/TLS) | ✅ 96ms |
| Protocol Confusion (SSH/TLS) | ✅ 94ms |
| Protocol Confusion (SMTP/TLS) | ✅ 90ms |
| Protocol Confusion (Multi-Layer) | ✅ 92ms |
| State Table Exhaustion | ✅ 2085ms |

---
*Generated automatically.*
