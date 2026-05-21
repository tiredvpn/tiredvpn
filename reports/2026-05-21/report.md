# TiredVPN Availability Report — 2026-05-21

**Date:** 2026-05-21  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_0 | 89ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 77ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_1 | 103ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_1 | 99ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 105ms | ✅ 131ms |
| REALITY Protocol | ✅ 190ms | ✅ 218ms |
| HTTP Polling (meek-style) | ✅ 156ms | ✅ 176ms |
| HTTP/2 Steganography | ✅ 137ms | ✅ 167ms |
| WebSocket Salamander | ✅ 149ms | ✅ 175ms |
| Traffic Morph (Yandex Video) | ✅ 131ms | ✅ 151ms |
| Traffic Morph (VK Video) | ✅ 126ms | ✅ 181ms |
| Traffic Morph (Baidu Video) | ✅ 139ms | ✅ 176ms |
| Traffic Morph (Aparat Video) | ✅ 125ms | ✅ 167ms |
| Geneva (Russia TSPU) | ✅ 145ms | ✅ 179ms |
| Geneva (China GFW) | ✅ 140ms | ✅ 181ms |
| Geneva (Iran DPI) | ✅ 128ms | ✅ 179ms |
| Anti-Probe Resistance | ✅ 884ms | ✅ 936ms |
| Protocol Confusion (DNS/TLS) | ✅ 89ms | ✅ 117ms |
| Protocol Confusion (HTTP/TLS) | ✅ 114ms | ✅ 103ms |
| Protocol Confusion (SSH/TLS) | ✅ 96ms | ✅ 131ms |
| Protocol Confusion (SMTP/TLS) | ✅ 101ms | ✅ 118ms |
| Protocol Confusion (Multi-Layer) | ✅ 105ms | ✅ 119ms |
| State Table Exhaustion | ✅ 2084ms | ✅ 2105ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 80ms | ✅ 124ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 132ms | ✅ 166ms |
| HTTP/2 Steganography | ✅ 114ms | ✅ 147ms |
| WebSocket Salamander | ✅ 118ms | ✅ 157ms |
| Traffic Morph (Yandex Video) | ✅ 119ms | ✅ 171ms |
| Traffic Morph (VK Video) | ✅ 116ms | ✅ 167ms |
| Traffic Morph (Baidu Video) | ✅ 144ms | ✅ 141ms |
| Traffic Morph (Aparat Video) | ✅ 117ms | ✅ 168ms |
| Geneva (Russia TSPU) | ✅ 160ms | ✅ 167ms |
| Geneva (China GFW) | ✅ 127ms | ✅ 164ms |
| Geneva (Iran DPI) | ✅ 133ms | ✅ 168ms |
| Anti-Probe Resistance | ✅ 885ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 86ms | ✅ 103ms |
| Protocol Confusion (HTTP/TLS) | ✅ 87ms | ✅ 99ms |
| Protocol Confusion (SSH/TLS) | ✅ 81ms | ✅ 124ms |
| Protocol Confusion (SMTP/TLS) | ✅ 77ms | ✅ 124ms |
| Protocol Confusion (Multi-Layer) | ✅ 95ms | ✅ 116ms |
| State Table Exhaustion | ✅ 2090ms | ❌ — |

---
*Generated automatically.*
