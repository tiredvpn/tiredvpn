# TiredVPN Availability Report — 2026-05-20

**Date:** 2026-05-20  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_2 | 91ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_1 | 83ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 118ms |
| MegaFon → Hetzner Nuremberg | 18 | 1 | confusion_3 | 103ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 116ms | ✅ 131ms |
| REALITY Protocol | ✅ 194ms | ✅ 211ms |
| HTTP Polling (meek-style) | ✅ 150ms | ✅ 160ms |
| HTTP/2 Steganography | ✅ 159ms | ✅ 187ms |
| WebSocket Salamander | ✅ 159ms | ✅ 173ms |
| Traffic Morph (Yandex Video) | ✅ 130ms | ✅ 180ms |
| Traffic Morph (VK Video) | ✅ 148ms | ✅ 184ms |
| Traffic Morph (Baidu Video) | ✅ 143ms | ✅ 179ms |
| Traffic Morph (Aparat Video) | ✅ 132ms | ✅ 167ms |
| Geneva (Russia TSPU) | ✅ 152ms | ✅ 176ms |
| Geneva (China GFW) | ✅ 179ms | ✅ 174ms |
| Geneva (Iran DPI) | ✅ 138ms | ✅ 184ms |
| Anti-Probe Resistance | ✅ 891ms | ✅ 924ms |
| Protocol Confusion (DNS/TLS) | ✅ 113ms | ✅ 118ms |
| Protocol Confusion (HTTP/TLS) | ✅ 99ms | ✅ 130ms |
| Protocol Confusion (SSH/TLS) | ✅ 91ms | ✅ 131ms |
| Protocol Confusion (SMTP/TLS) | ✅ 99ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 101ms | ✅ 131ms |
| State Table Exhaustion | ✅ 2088ms | ✅ 2120ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 90ms | ✅ 126ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 120ms | ✅ 175ms |
| HTTP/2 Steganography | ✅ 126ms | ✅ 174ms |
| WebSocket Salamander | ✅ 123ms | ✅ 157ms |
| Traffic Morph (Yandex Video) | ✅ 129ms | ✅ 142ms |
| Traffic Morph (VK Video) | ✅ 128ms | ✅ 175ms |
| Traffic Morph (Baidu Video) | ✅ 141ms | ✅ 173ms |
| Traffic Morph (Aparat Video) | ✅ 123ms | ✅ 175ms |
| Geneva (Russia TSPU) | ✅ 194ms | ✅ 175ms |
| Geneva (China GFW) | ✅ 123ms | ✅ 172ms |
| Geneva (Iran DPI) | ✅ 124ms | ✅ 173ms |
| Anti-Probe Resistance | ✅ 901ms | ✅ 924ms |
| Protocol Confusion (DNS/TLS) | ✅ 84ms | ✅ 119ms |
| Protocol Confusion (HTTP/TLS) | ✅ 83ms | ✅ 121ms |
| Protocol Confusion (SSH/TLS) | ✅ 84ms | ✅ 120ms |
| Protocol Confusion (SMTP/TLS) | ✅ 84ms | ✅ 103ms |
| Protocol Confusion (Multi-Layer) | ✅ 96ms | ✅ 111ms |
| State Table Exhaustion | ✅ 2084ms | ✅ 2112ms |

---
*Generated automatically.*
