# TiredVPN Availability Report — 2026-06-05

**Date:** 2026-06-05  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_2 | 97ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_0 | 80ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_3 | 104ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_2 | 100ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 113ms | ✅ 134ms |
| REALITY Protocol | ✅ 235ms | ✅ 226ms |
| HTTP Polling (meek-style) | ✅ 176ms | ✅ 176ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 146ms | ✅ 181ms |
| Traffic Morph (Yandex Video) | ✅ 138ms | ✅ 180ms |
| Traffic Morph (VK Video) | ✅ 129ms | ✅ 170ms |
| Traffic Morph (Baidu Video) | ✅ 135ms | ✅ 179ms |
| Traffic Morph (Aparat Video) | ✅ 137ms | ✅ 173ms |
| Geneva (Russia TSPU) | ✅ 168ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 148ms | ✅ 181ms |
| Geneva (Iran DPI) | ✅ 157ms | ✅ 158ms |
| Anti-Probe Resistance | ✅ 900ms | ✅ 943ms |
| Protocol Confusion (DNS/TLS) | ✅ 112ms | ✅ 134ms |
| Protocol Confusion (HTTP/TLS) | ✅ 112ms | ✅ 130ms |
| Protocol Confusion (SSH/TLS) | ✅ 97ms | ✅ 129ms |
| Protocol Confusion (SMTP/TLS) | ✅ 116ms | ✅ 104ms |
| Protocol Confusion (Multi-Layer) | ✅ 121ms | ✅ 130ms |
| State Table Exhaustion | ✅ 2098ms | ✅ 2114ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 89ms | ✅ 124ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 117ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 122ms | ✅ 166ms |
| WebSocket Salamander | ✅ 119ms | ✅ 171ms |
| Traffic Morph (Yandex Video) | ✅ 131ms | ✅ 171ms |
| Traffic Morph (VK Video) | ✅ 133ms | ✅ 165ms |
| Traffic Morph (Baidu Video) | ✅ 123ms | ✅ 142ms |
| Traffic Morph (Aparat Video) | ✅ 131ms | ✅ 148ms |
| Geneva (Russia TSPU) | ✅ 170ms | ✅ 164ms |
| Geneva (China GFW) | ✅ 137ms | ✅ 157ms |
| Geneva (Iran DPI) | ✅ 127ms | ✅ 166ms |
| Anti-Probe Resistance | ✅ 888ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 80ms | ✅ 124ms |
| Protocol Confusion (HTTP/TLS) | ✅ 89ms | ✅ 117ms |
| Protocol Confusion (SSH/TLS) | ✅ 88ms | ✅ 100ms |
| Protocol Confusion (SMTP/TLS) | ✅ 89ms | ✅ 117ms |
| Protocol Confusion (Multi-Layer) | ✅ 92ms | ✅ 124ms |
| State Table Exhaustion | ✅ 2081ms | ❌ — |

---
*Generated automatically.*
