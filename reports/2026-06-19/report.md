# TiredVPN Availability Report — 2026-06-19

**Date:** 2026-06-19  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_1 | 120ms |
| Rostelecom → Hetzner Nuremberg | 16 | 3 | confusion_2 | 87ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 169ms |
| WebSocket Salamander | ✅ 233ms |
| Traffic Morph (Yandex Video) | ✅ 160ms |
| Traffic Morph (VK Video) | ✅ 156ms |
| Traffic Morph (Baidu Video) | ✅ 129ms |
| Traffic Morph (Aparat Video) | ✅ 151ms |
| Geneva (Russia TSPU) | ✅ 205ms |
| Geneva (China GFW) | ✅ 190ms |
| Geneva (Iran DPI) | ✅ 186ms |
| Anti-Probe Resistance | ✅ 933ms |
| Protocol Confusion (DNS/TLS) | ✅ 132ms |
| Protocol Confusion (HTTP/TLS) | ✅ 120ms |
| Protocol Confusion (SSH/TLS) | ✅ 160ms |
| Protocol Confusion (SMTP/TLS) | ✅ 164ms |
| Protocol Confusion (Multi-Layer) | ✅ 124ms |
| State Table Exhaustion | ✅ 2096ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ❌ — |
| REALITY Protocol | ❌ — |
| HTTP Polling (meek-style) | ❌ — |
| HTTP/2 Steganography | ✅ 134ms |
| WebSocket Salamander | ✅ 129ms |
| Traffic Morph (Yandex Video) | ✅ 139ms |
| Traffic Morph (VK Video) | ✅ 116ms |
| Traffic Morph (Baidu Video) | ✅ 140ms |
| Traffic Morph (Aparat Video) | ✅ 128ms |
| Geneva (Russia TSPU) | ✅ 135ms |
| Geneva (China GFW) | ✅ 130ms |
| Geneva (Iran DPI) | ✅ 130ms |
| Anti-Probe Resistance | ✅ 888ms |
| Protocol Confusion (DNS/TLS) | ✅ 89ms |
| Protocol Confusion (HTTP/TLS) | ✅ 92ms |
| Protocol Confusion (SSH/TLS) | ✅ 87ms |
| Protocol Confusion (SMTP/TLS) | ✅ 98ms |
| Protocol Confusion (Multi-Layer) | ✅ 99ms |
| State Table Exhaustion | ✅ 2078ms |

---
*Generated automatically.*
