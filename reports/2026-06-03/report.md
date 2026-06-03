# TiredVPN Availability Report — 2026-06-03

**Date:** 2026-06-03  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_4 | 93ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_1 | 81ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_1 | 104ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_1 | 100ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 114ms | ✅ 134ms |
| REALITY Protocol | ✅ 213ms | ✅ 223ms |
| HTTP Polling (meek-style) | ✅ 152ms | ✅ 173ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 155ms | ✅ 174ms |
| Traffic Morph (Yandex Video) | ✅ 133ms | ✅ 167ms |
| Traffic Morph (VK Video) | ✅ 141ms | ✅ 169ms |
| Traffic Morph (Baidu Video) | ✅ 131ms | ✅ 178ms |
| Traffic Morph (Aparat Video) | ✅ 142ms | ✅ 167ms |
| Geneva (Russia TSPU) | ✅ 148ms | ✅ 185ms |
| Geneva (China GFW) | ✅ 139ms | ✅ 174ms |
| Geneva (Iran DPI) | ✅ 140ms | ✅ 166ms |
| Anti-Probe Resistance | ✅ 893ms | ✅ 941ms |
| Protocol Confusion (DNS/TLS) | ✅ 99ms | ✅ 119ms |
| Protocol Confusion (HTTP/TLS) | ✅ 97ms | ✅ 104ms |
| Protocol Confusion (SSH/TLS) | ✅ 102ms | ✅ 125ms |
| Protocol Confusion (SMTP/TLS) | ✅ 116ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 93ms | ✅ 133ms |
| State Table Exhaustion | ✅ 2096ms | ✅ 2099ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 90ms | ✅ 123ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 135ms | ✅ 151ms |
| HTTP/2 Steganography | ✅ 118ms | ✅ 163ms |
| WebSocket Salamander | ✅ 137ms | ✅ 165ms |
| Traffic Morph (Yandex Video) | ✅ 120ms | ✅ 169ms |
| Traffic Morph (VK Video) | ✅ 122ms | ✅ 170ms |
| Traffic Morph (Baidu Video) | ✅ 121ms | ✅ 170ms |
| Traffic Morph (Aparat Video) | ✅ 138ms | ✅ 144ms |
| Geneva (Russia TSPU) | ✅ 179ms | ✅ 168ms |
| Geneva (China GFW) | ✅ 131ms | ✅ 167ms |
| Geneva (Iran DPI) | ✅ 121ms | ✅ 166ms |
| Anti-Probe Resistance | ✅ 907ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 95ms | ✅ 124ms |
| Protocol Confusion (HTTP/TLS) | ✅ 81ms | ✅ 100ms |
| Protocol Confusion (SSH/TLS) | ✅ 90ms | ✅ 104ms |
| Protocol Confusion (SMTP/TLS) | ✅ 90ms | ✅ 127ms |
| Protocol Confusion (Multi-Layer) | ✅ 83ms | ✅ 124ms |
| State Table Exhaustion | ✅ 2081ms | ✅ 2108ms |

---
*Generated automatically.*
