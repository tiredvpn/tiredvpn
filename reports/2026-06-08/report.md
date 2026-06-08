# TiredVPN Availability Report — 2026-06-08

**Date:** 2026-06-08  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_4 | 158ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_2 | 81ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_4 | 125ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_1 | 104ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 158ms | ✅ 132ms |
| REALITY Protocol | ✅ 300ms | ✅ 225ms |
| HTTP Polling (meek-style) | ✅ 216ms | ✅ 186ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 230ms | ✅ 184ms |
| Traffic Morph (Yandex Video) | ✅ 202ms | ✅ 186ms |
| Traffic Morph (VK Video) | ✅ 226ms | ✅ 171ms |
| Traffic Morph (Baidu Video) | ✅ 225ms | ✅ 185ms |
| Traffic Morph (Aparat Video) | ✅ 228ms | ✅ 179ms |
| Geneva (Russia TSPU) | ✅ 233ms | ✅ 175ms |
| Geneva (China GFW) | ✅ 231ms | ✅ 172ms |
| Geneva (Iran DPI) | ✅ 218ms | ✅ 167ms |
| Anti-Probe Resistance | ✅ 978ms | ✅ 921ms |
| Protocol Confusion (DNS/TLS) | ✅ 161ms | ✅ 125ms |
| Protocol Confusion (HTTP/TLS) | ✅ 159ms | ✅ 128ms |
| Protocol Confusion (SSH/TLS) | ✅ 174ms | ✅ 128ms |
| Protocol Confusion (SMTP/TLS) | ✅ 165ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 158ms | ✅ 125ms |
| State Table Exhaustion | ✅ 2084ms | ✅ 2168ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 88ms | ✅ 120ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 122ms | ✅ 164ms |
| HTTP/2 Steganography | ✅ 137ms | ✅ 169ms |
| WebSocket Salamander | ✅ 118ms | ✅ 165ms |
| Traffic Morph (Yandex Video) | ✅ 124ms | ✅ 144ms |
| Traffic Morph (VK Video) | ✅ 125ms | ✅ 138ms |
| Traffic Morph (Baidu Video) | ✅ 124ms | ✅ 170ms |
| Traffic Morph (Aparat Video) | ✅ 120ms | ✅ 170ms |
| Geneva (Russia TSPU) | ✅ 180ms | ✅ 169ms |
| Geneva (China GFW) | ✅ 157ms | ✅ 154ms |
| Geneva (Iran DPI) | ✅ 133ms | ✅ 138ms |
| Anti-Probe Resistance | ✅ 890ms | ✅ 922ms |
| Protocol Confusion (DNS/TLS) | ✅ 92ms | ✅ 118ms |
| Protocol Confusion (HTTP/TLS) | ✅ 92ms | ✅ 104ms |
| Protocol Confusion (SSH/TLS) | ✅ 81ms | ✅ 105ms |
| Protocol Confusion (SMTP/TLS) | ✅ 84ms | ✅ 120ms |
| Protocol Confusion (Multi-Layer) | ✅ 90ms | ✅ 119ms |
| State Table Exhaustion | ✅ 2090ms | ❌ — |

---
*Generated automatically.*
