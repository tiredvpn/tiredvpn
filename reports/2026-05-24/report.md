# TiredVPN Availability Report — 2026-05-24

**Date:** 2026-05-24  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_1 | 84ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | quic_salamander | 83ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_1 | 127ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_1 | 104ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 121ms | ✅ 128ms |
| REALITY Protocol | ✅ 200ms | ✅ 327ms |
| HTTP Polling (meek-style) | ✅ 156ms | ✅ 165ms |
| HTTP/2 Steganography | ✅ 129ms | ✅ 170ms |
| WebSocket Salamander | ✅ 149ms | ✅ 182ms |
| Traffic Morph (Yandex Video) | ✅ 132ms | ✅ 169ms |
| Traffic Morph (VK Video) | ✅ 135ms | ✅ 182ms |
| Traffic Morph (Baidu Video) | ✅ 138ms | ✅ 178ms |
| Traffic Morph (Aparat Video) | ✅ 144ms | ✅ 177ms |
| Geneva (Russia TSPU) | ✅ 189ms | ✅ 177ms |
| Geneva (China GFW) | ✅ 133ms | ✅ 169ms |
| Geneva (Iran DPI) | ✅ 150ms | ✅ 183ms |
| Anti-Probe Resistance | ✅ 949ms | ✅ 922ms |
| Protocol Confusion (DNS/TLS) | ✅ 109ms | ✅ 127ms |
| Protocol Confusion (HTTP/TLS) | ✅ 84ms | ✅ 127ms |
| Protocol Confusion (SSH/TLS) | ✅ 114ms | ✅ 131ms |
| Protocol Confusion (SMTP/TLS) | ✅ 111ms | ✅ 127ms |
| Protocol Confusion (Multi-Layer) | ✅ 119ms | ✅ 127ms |
| State Table Exhaustion | ✅ 2097ms | ✅ 2220ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 83ms | ✅ 127ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 120ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 136ms | ✅ 171ms |
| WebSocket Salamander | ✅ 136ms | ✅ 167ms |
| Traffic Morph (Yandex Video) | ✅ 134ms | ✅ 141ms |
| Traffic Morph (VK Video) | ✅ 136ms | ✅ 175ms |
| Traffic Morph (Baidu Video) | ✅ 122ms | ✅ 146ms |
| Traffic Morph (Aparat Video) | ✅ 135ms | ✅ 176ms |
| Geneva (Russia TSPU) | ✅ 179ms | ✅ 168ms |
| Geneva (China GFW) | ✅ 133ms | ✅ 171ms |
| Geneva (Iran DPI) | ✅ 123ms | ✅ 146ms |
| Anti-Probe Resistance | ✅ 876ms | ✅ 909ms |
| Protocol Confusion (DNS/TLS) | ✅ 95ms | ✅ 120ms |
| Protocol Confusion (HTTP/TLS) | ✅ 93ms | ✅ 104ms |
| Protocol Confusion (SSH/TLS) | ✅ 86ms | ✅ 118ms |
| Protocol Confusion (SMTP/TLS) | ✅ 88ms | ✅ 115ms |
| Protocol Confusion (Multi-Layer) | ✅ 83ms | ✅ 124ms |
| State Table Exhaustion | ✅ 2099ms | ❌ — |

---
*Generated automatically.*
