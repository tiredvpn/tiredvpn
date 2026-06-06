# TiredVPN Availability Report — 2026-06-06

**Date:** 2026-06-06  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_4 | 101ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 79ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_0 | 113ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_1 | 99ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 115ms | ✅ 133ms |
| REALITY Protocol | ✅ 202ms | ✅ 230ms |
| HTTP Polling (meek-style) | ✅ 144ms | ✅ 178ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 130ms | ✅ 154ms |
| Traffic Morph (Yandex Video) | ✅ 132ms | ✅ 174ms |
| Traffic Morph (VK Video) | ✅ 129ms | ✅ 174ms |
| Traffic Morph (Baidu Video) | ✅ 127ms | ✅ 143ms |
| Traffic Morph (Aparat Video) | ✅ 140ms | ✅ 174ms |
| Geneva (Russia TSPU) | ✅ 168ms | ✅ 172ms |
| Geneva (China GFW) | ✅ 158ms | ✅ 179ms |
| Geneva (Iran DPI) | ✅ 138ms | ✅ 172ms |
| Anti-Probe Resistance | ✅ 899ms | ✅ 941ms |
| Protocol Confusion (DNS/TLS) | ✅ 110ms | ✅ 113ms |
| Protocol Confusion (HTTP/TLS) | ✅ 106ms | ✅ 120ms |
| Protocol Confusion (SSH/TLS) | ✅ 110ms | ✅ 126ms |
| Protocol Confusion (SMTP/TLS) | ✅ 105ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 101ms | ✅ 124ms |
| State Table Exhaustion | ✅ 3121ms | ✅ 2110ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 86ms | ✅ 119ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 128ms | ✅ 170ms |
| HTTP/2 Steganography | ✅ 116ms | ✅ 137ms |
| WebSocket Salamander | ✅ 126ms | ✅ 169ms |
| Traffic Morph (Yandex Video) | ✅ 137ms | ✅ 140ms |
| Traffic Morph (VK Video) | ✅ 128ms | ✅ 138ms |
| Traffic Morph (Baidu Video) | ✅ 132ms | ✅ 133ms |
| Traffic Morph (Aparat Video) | ✅ 126ms | ✅ 151ms |
| Geneva (Russia TSPU) | ✅ 125ms | ✅ 166ms |
| Geneva (China GFW) | ✅ 123ms | ✅ 166ms |
| Geneva (Iran DPI) | ✅ 128ms | ✅ 166ms |
| Anti-Probe Resistance | ✅ 880ms | ✅ 925ms |
| Protocol Confusion (DNS/TLS) | ✅ 90ms | ✅ 104ms |
| Protocol Confusion (HTTP/TLS) | ✅ 85ms | ✅ 99ms |
| Protocol Confusion (SSH/TLS) | ✅ 88ms | ✅ 103ms |
| Protocol Confusion (SMTP/TLS) | ✅ 79ms | ✅ 112ms |
| Protocol Confusion (Multi-Layer) | ✅ 88ms | ✅ 119ms |
| State Table Exhaustion | ✅ 2078ms | ✅ 2094ms |

---
*Generated automatically.*
