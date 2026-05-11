# TiredVPN Availability Report — 2026-05-11

**Date:** 2026-05-11  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_2 | 88ms |
| Rostelecom → Hetzner Nuremberg | 19 | 0 | confusion_1 | 80ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_2 | 123ms |
| MegaFon → Hetzner Nuremberg | 19 | 0 | confusion_0 | 107ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 110ms | ✅ 131ms |
| REALITY Protocol | ✅ 192ms | ✅ 228ms |
| HTTP Polling (meek-style) | ✅ 136ms | ✅ 173ms |
| HTTP/2 Steganography | ✅ 143ms | ✅ 165ms |
| WebSocket Salamander | ✅ 156ms | ✅ 173ms |
| Traffic Morph (Yandex Video) | ✅ 140ms | ✅ 146ms |
| Traffic Morph (VK Video) | ✅ 122ms | ✅ 172ms |
| Traffic Morph (Baidu Video) | ✅ 134ms | ✅ 170ms |
| Traffic Morph (Aparat Video) | ✅ 131ms | ✅ 172ms |
| Geneva (Russia TSPU) | ✅ 179ms | ✅ 187ms |
| Geneva (China GFW) | ✅ 156ms | ✅ 170ms |
| Geneva (Iran DPI) | ✅ 136ms | ✅ 176ms |
| Anti-Probe Resistance | ✅ 899ms | ✅ 1038ms |
| Protocol Confusion (DNS/TLS) | ✅ 92ms | ✅ 125ms |
| Protocol Confusion (HTTP/TLS) | ✅ 101ms | ✅ 133ms |
| Protocol Confusion (SSH/TLS) | ✅ 88ms | ✅ 123ms |
| Protocol Confusion (SMTP/TLS) | ✅ 96ms | ✅ 135ms |
| Protocol Confusion (Multi-Layer) | ✅ 96ms | ✅ 125ms |
| State Table Exhaustion | ✅ 2091ms | ✅ 2176ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 93ms | ✅ 126ms |
| REALITY Protocol | ✅ 174ms | ✅ 190ms |
| HTTP Polling (meek-style) | ✅ 131ms | ✅ 140ms |
| HTTP/2 Steganography | ✅ 118ms | ✅ 169ms |
| WebSocket Salamander | ✅ 138ms | ✅ 168ms |
| Traffic Morph (Yandex Video) | ✅ 138ms | ✅ 168ms |
| Traffic Morph (VK Video) | ✅ 115ms | ✅ 138ms |
| Traffic Morph (Baidu Video) | ✅ 138ms | ✅ 172ms |
| Traffic Morph (Aparat Video) | ✅ 116ms | ✅ 173ms |
| Geneva (Russia TSPU) | ✅ 122ms | ✅ 139ms |
| Geneva (China GFW) | ✅ 157ms | ✅ 142ms |
| Geneva (Iran DPI) | ✅ 129ms | ✅ 157ms |
| Anti-Probe Resistance | ✅ 891ms | ✅ 924ms |
| Protocol Confusion (DNS/TLS) | ✅ 87ms | ✅ 107ms |
| Protocol Confusion (HTTP/TLS) | ✅ 80ms | ✅ 113ms |
| Protocol Confusion (SSH/TLS) | ✅ 83ms | ✅ 108ms |
| Protocol Confusion (SMTP/TLS) | ✅ 83ms | ✅ 121ms |
| Protocol Confusion (Multi-Layer) | ✅ 83ms | ✅ 112ms |
| State Table Exhaustion | ✅ 2088ms | ✅ 2109ms |

---
*Generated automatically.*
