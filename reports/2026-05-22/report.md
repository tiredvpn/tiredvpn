# TiredVPN Availability Report — 2026-05-22

**Date:** 2026-05-22  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_1 | 96ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 77ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 461ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_3 | 116ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 124ms | ✅ 487ms |
| REALITY Protocol | ✅ 207ms | ✅ 1058ms |
| HTTP Polling (meek-style) | ✅ 148ms | ✅ 688ms |
| HTTP/2 Steganography | ✅ 142ms | ✅ 666ms |
| WebSocket Salamander | ✅ 149ms | ✅ 673ms |
| Traffic Morph (Yandex Video) | ✅ 138ms | ✅ 683ms |
| Traffic Morph (VK Video) | ✅ 124ms | ✅ 670ms |
| Traffic Morph (Baidu Video) | ✅ 150ms | ✅ 681ms |
| Traffic Morph (Aparat Video) | ✅ 138ms | ✅ 686ms |
| Geneva (Russia TSPU) | ✅ 185ms | ✅ 693ms |
| Geneva (China GFW) | ✅ 158ms | ✅ 691ms |
| Geneva (Iran DPI) | ✅ 166ms | ✅ 687ms |
| Anti-Probe Resistance | ✅ 914ms | ✅ 1465ms |
| Protocol Confusion (DNS/TLS) | ✅ 126ms | ✅ 461ms |
| Protocol Confusion (HTTP/TLS) | ✅ 96ms | ✅ 475ms |
| Protocol Confusion (SSH/TLS) | ✅ 100ms | ✅ 489ms |
| Protocol Confusion (SMTP/TLS) | ✅ 124ms | ✅ 480ms |
| Protocol Confusion (Multi-Layer) | ✅ 97ms | ✅ 480ms |
| State Table Exhaustion | ✅ 2094ms | ✅ 2197ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 96ms | ✅ 126ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 127ms | ✅ 141ms |
| HTTP/2 Steganography | ✅ 133ms | ✅ 171ms |
| WebSocket Salamander | ✅ 125ms | ✅ 175ms |
| Traffic Morph (Yandex Video) | ✅ 114ms | ✅ 167ms |
| Traffic Morph (VK Video) | ✅ 120ms | ✅ 148ms |
| Traffic Morph (Baidu Video) | ✅ 139ms | ✅ 152ms |
| Traffic Morph (Aparat Video) | ✅ 133ms | ✅ 168ms |
| Geneva (Russia TSPU) | ✅ 132ms | ✅ 177ms |
| Geneva (China GFW) | ✅ 122ms | ✅ 144ms |
| Geneva (Iran DPI) | ✅ 121ms | ✅ 167ms |
| Anti-Probe Resistance | ✅ 887ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 83ms | ✅ 117ms |
| Protocol Confusion (HTTP/TLS) | ✅ 88ms | ✅ 117ms |
| Protocol Confusion (SSH/TLS) | ✅ 87ms | ✅ 126ms |
| Protocol Confusion (SMTP/TLS) | ✅ 77ms | ✅ 116ms |
| Protocol Confusion (Multi-Layer) | ✅ 81ms | ✅ 126ms |
| State Table Exhaustion | ✅ 2083ms | ❌ — |

---
*Generated automatically.*
