# TiredVPN Availability Report — 2026-05-25

**Date:** 2026-05-25  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | quic_salamander | 143ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | confusion_0 | 81ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_3 | 125ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_1 | 102ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 143ms | ✅ 132ms |
| REALITY Protocol | ✅ 256ms | ✅ 207ms |
| HTTP Polling (meek-style) | ✅ 194ms | ✅ 168ms |
| HTTP/2 Steganography | ✅ 198ms | ✅ 158ms |
| WebSocket Salamander | ✅ 194ms | ✅ 167ms |
| Traffic Morph (Yandex Video) | ✅ 168ms | ✅ 174ms |
| Traffic Morph (VK Video) | ✅ 171ms | ✅ 180ms |
| Traffic Morph (Baidu Video) | ✅ 173ms | ✅ 180ms |
| Traffic Morph (Aparat Video) | ✅ 166ms | ✅ 144ms |
| Geneva (Russia TSPU) | ✅ 199ms | ✅ 186ms |
| Geneva (China GFW) | ✅ 199ms | ✅ 184ms |
| Geneva (Iran DPI) | ✅ 202ms | ✅ 173ms |
| Anti-Probe Resistance | ✅ 952ms | ✅ 925ms |
| Protocol Confusion (DNS/TLS) | ✅ 144ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 153ms | ✅ 126ms |
| Protocol Confusion (SSH/TLS) | ✅ 148ms | ✅ 127ms |
| Protocol Confusion (SMTP/TLS) | ✅ 147ms | ✅ 125ms |
| Protocol Confusion (Multi-Layer) | ✅ 154ms | ✅ 130ms |
| State Table Exhaustion | ✅ 2103ms | ✅ 2226ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 94ms | ✅ 115ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 122ms | ✅ 141ms |
| HTTP/2 Steganography | ✅ 128ms | ✅ 140ms |
| WebSocket Salamander | ✅ 135ms | ✅ 139ms |
| Traffic Morph (Yandex Video) | ✅ 135ms | ✅ 149ms |
| Traffic Morph (VK Video) | ✅ 131ms | ✅ 151ms |
| Traffic Morph (Baidu Video) | ✅ 144ms | ✅ 146ms |
| Traffic Morph (Aparat Video) | ✅ 123ms | ✅ 144ms |
| Geneva (Russia TSPU) | ✅ 136ms | ✅ 174ms |
| Geneva (China GFW) | ✅ 152ms | ✅ 139ms |
| Geneva (Iran DPI) | ✅ 133ms | ✅ 169ms |
| Anti-Probe Resistance | ❌ — | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 81ms | ✅ 123ms |
| Protocol Confusion (HTTP/TLS) | ✅ 95ms | ✅ 102ms |
| Protocol Confusion (SSH/TLS) | ✅ 88ms | ✅ 115ms |
| Protocol Confusion (SMTP/TLS) | ✅ 92ms | ✅ 114ms |
| Protocol Confusion (Multi-Layer) | ✅ 98ms | ✅ 121ms |
| State Table Exhaustion | ✅ 2077ms | ✅ 2105ms |

---
*Generated automatically.*
