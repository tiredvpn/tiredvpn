# TiredVPN Availability Report — 2026-06-23

**Date:** 2026-06-23  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_2 | 135ms |
| Rostelecom → Hetzner Nuremberg | 16 | 3 | confusion_1 | 84ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 182ms |
| WebSocket Salamander | ✅ 196ms |
| Traffic Morph (Yandex Video) | ✅ 175ms |
| Traffic Morph (VK Video) | ✅ 155ms |
| Traffic Morph (Baidu Video) | ✅ 1130ms |
| Traffic Morph (Aparat Video) | ✅ 236ms |
| Geneva (Russia TSPU) | ✅ 218ms |
| Geneva (China GFW) | ✅ 184ms |
| Geneva (Iran DPI) | ✅ 201ms |
| Anti-Probe Resistance | ✅ 963ms |
| Protocol Confusion (DNS/TLS) | ✅ 149ms |
| Protocol Confusion (HTTP/TLS) | ✅ 153ms |
| Protocol Confusion (SSH/TLS) | ✅ 135ms |
| Protocol Confusion (SMTP/TLS) | ✅ 158ms |
| Protocol Confusion (Multi-Layer) | ✅ 140ms |
| State Table Exhaustion | ✅ 2096ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 129ms |
| WebSocket Salamander | ✅ 124ms |
| Traffic Morph (Yandex Video) | ✅ 133ms |
| Traffic Morph (VK Video) | ✅ 128ms |
| Traffic Morph (Baidu Video) | ✅ 144ms |
| Traffic Morph (Aparat Video) | ✅ 129ms |
| Geneva (Russia TSPU) | ✅ 173ms |
| Geneva (China GFW) | ✅ 135ms |
| Geneva (Iran DPI) | ✅ 130ms |
| Anti-Probe Resistance | ✅ 894ms |
| Protocol Confusion (DNS/TLS) | ✅ 94ms |
| Protocol Confusion (HTTP/TLS) | ✅ 84ms |
| Protocol Confusion (SSH/TLS) | ✅ 87ms |
| Protocol Confusion (SMTP/TLS) | ✅ 84ms |
| Protocol Confusion (Multi-Layer) | ✅ 88ms |
| State Table Exhaustion | ✅ 2091ms |

---
*Generated automatically.*
