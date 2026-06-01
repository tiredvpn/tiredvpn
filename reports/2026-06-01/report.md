# TiredVPN Availability Report — 2026-06-01

**Date:** 2026-06-01  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_0 | 95ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | confusion_4 | 81ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_4 | 135ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_4 | 97ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 120ms | ✅ 152ms |
| REALITY Protocol | ✅ 217ms | ✅ 247ms |
| HTTP Polling (meek-style) | ✅ 145ms | ✅ 203ms |
| HTTP/2 Steganography | ✅ 155ms | ✅ 199ms |
| WebSocket Salamander | ✅ 147ms | ✅ 199ms |
| Traffic Morph (Yandex Video) | ✅ 139ms | ✅ 167ms |
| Traffic Morph (VK Video) | ✅ 144ms | ✅ 181ms |
| Traffic Morph (Baidu Video) | ✅ 143ms | ✅ 173ms |
| Traffic Morph (Aparat Video) | ✅ 151ms | ✅ 163ms |
| Geneva (Russia TSPU) | ✅ 176ms | ✅ 199ms |
| Geneva (China GFW) | ✅ 179ms | ✅ 185ms |
| Geneva (Iran DPI) | ✅ 150ms | ✅ 182ms |
| Anti-Probe Resistance | ✅ 905ms | ✅ 952ms |
| Protocol Confusion (DNS/TLS) | ✅ 95ms | ✅ 145ms |
| Protocol Confusion (HTTP/TLS) | ✅ 110ms | ✅ 140ms |
| Protocol Confusion (SSH/TLS) | ✅ 100ms | ✅ 139ms |
| Protocol Confusion (SMTP/TLS) | ✅ 116ms | ✅ 141ms |
| Protocol Confusion (Multi-Layer) | ✅ 102ms | ✅ 135ms |
| State Table Exhaustion | ✅ 2089ms | ✅ 2144ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 91ms | ✅ 117ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 148ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 125ms | ✅ 137ms |
| WebSocket Salamander | ✅ 133ms | ✅ 169ms |
| Traffic Morph (Yandex Video) | ✅ 127ms | ✅ 174ms |
| Traffic Morph (VK Video) | ✅ 135ms | ✅ 149ms |
| Traffic Morph (Baidu Video) | ✅ 127ms | ✅ 147ms |
| Traffic Morph (Aparat Video) | ✅ 115ms | ✅ 142ms |
| Geneva (Russia TSPU) | ✅ 199ms | ✅ 141ms |
| Geneva (China GFW) | ✅ 130ms | ✅ 169ms |
| Geneva (Iran DPI) | ✅ 120ms | ✅ 169ms |
| Anti-Probe Resistance | ❌ — | ✅ 898ms |
| Protocol Confusion (DNS/TLS) | ✅ 91ms | ✅ 117ms |
| Protocol Confusion (HTTP/TLS) | ✅ 91ms | ✅ 99ms |
| Protocol Confusion (SSH/TLS) | ✅ 88ms | ✅ 119ms |
| Protocol Confusion (SMTP/TLS) | ✅ 89ms | ✅ 105ms |
| Protocol Confusion (Multi-Layer) | ✅ 81ms | ✅ 97ms |
| State Table Exhaustion | ✅ 2080ms | ❌ — |

---
*Generated automatically.*
