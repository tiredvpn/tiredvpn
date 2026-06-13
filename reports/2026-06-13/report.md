# TiredVPN Availability Report — 2026-06-13

**Date:** 2026-06-13  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_0 | 101ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | confusion_0 | 80ms |
| MegaFon → Hetzner Amsterdam | 16 | 3 | confusion_0 | 367ms |
| MegaFon → Hetzner Nuremberg | 13 | 6 | confusion_1 | 1117ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 118ms | ✅ 421ms |
| REALITY Protocol | ✅ 210ms | ✅ 451ms |
| HTTP Polling (meek-style) | ✅ 174ms | ❌ — |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 140ms | ✅ 433ms |
| Traffic Morph (Yandex Video) | ✅ 123ms | ✅ 427ms |
| Traffic Morph (VK Video) | ✅ 125ms | ✅ 427ms |
| Traffic Morph (Baidu Video) | ✅ 141ms | ✅ 433ms |
| Traffic Morph (Aparat Video) | ✅ 124ms | ✅ 475ms |
| Geneva (Russia TSPU) | ✅ 174ms | ✅ 432ms |
| Geneva (China GFW) | ✅ 131ms | ✅ 474ms |
| Geneva (Iran DPI) | ✅ 172ms | ❌ — |
| Anti-Probe Resistance | ✅ 899ms | ✅ 1230ms |
| Protocol Confusion (DNS/TLS) | ✅ 101ms | ✅ 367ms |
| Protocol Confusion (HTTP/TLS) | ✅ 117ms | ✅ 404ms |
| Protocol Confusion (SSH/TLS) | ✅ 113ms | ✅ 404ms |
| Protocol Confusion (SMTP/TLS) | ✅ 110ms | ✅ 403ms |
| Protocol Confusion (Multi-Layer) | ✅ 121ms | ✅ 378ms |
| State Table Exhaustion | ✅ 2096ms | ✅ 2178ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 94ms | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 142ms | ❌ — |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 131ms | ✅ 1497ms |
| Traffic Morph (Yandex Video) | ✅ 144ms | ✅ 1315ms |
| Traffic Morph (VK Video) | ✅ 135ms | ✅ 1297ms |
| Traffic Morph (Baidu Video) | ✅ 119ms | ✅ 1337ms |
| Traffic Morph (Aparat Video) | ✅ 123ms | ✅ 1337ms |
| Geneva (Russia TSPU) | ✅ 180ms | ✅ 1633ms |
| Geneva (China GFW) | ✅ 150ms | ✅ 1627ms |
| Geneva (Iran DPI) | ✅ 120ms | ❌ — |
| Anti-Probe Resistance | ✅ 903ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 80ms | ✅ 1177ms |
| Protocol Confusion (HTTP/TLS) | ✅ 86ms | ✅ 1117ms |
| Protocol Confusion (SSH/TLS) | ✅ 91ms | ✅ 1217ms |
| Protocol Confusion (SMTP/TLS) | ✅ 86ms | ✅ 1229ms |
| Protocol Confusion (Multi-Layer) | ✅ 80ms | ✅ 1257ms |
| State Table Exhaustion | ✅ 2090ms | ✅ 2190ms |

---
*Generated automatically.*
