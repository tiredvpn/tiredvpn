# TiredVPN Availability Report — 2026-06-02

**Date:** 2026-06-02  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_2 | 236ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_3 | 81ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_2 | 141ms |
| MegaFon → Hetzner Nuremberg | 16 | 3 | confusion_2 | 99ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 285ms | ✅ 142ms |
| REALITY Protocol | ✅ 412ms | ✅ 233ms |
| HTTP Polling (meek-style) | ✅ 295ms | ✅ 188ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 294ms | ✅ 170ms |
| Traffic Morph (Yandex Video) | ✅ 295ms | ✅ 187ms |
| Traffic Morph (VK Video) | ✅ 293ms | ✅ 166ms |
| Traffic Morph (Baidu Video) | ✅ 290ms | ✅ 181ms |
| Traffic Morph (Aparat Video) | ✅ 300ms | ✅ 187ms |
| Geneva (Russia TSPU) | ✅ 355ms | ✅ 169ms |
| Geneva (China GFW) | ✅ 297ms | ✅ 198ms |
| Geneva (Iran DPI) | ✅ 305ms | ✅ 184ms |
| Anti-Probe Resistance | ✅ 1057ms | ✅ 950ms |
| Protocol Confusion (DNS/TLS) | ✅ 250ms | ✅ 149ms |
| Protocol Confusion (HTTP/TLS) | ✅ 243ms | ✅ 143ms |
| Protocol Confusion (SSH/TLS) | ✅ 236ms | ✅ 141ms |
| Protocol Confusion (SMTP/TLS) | ✅ 247ms | ✅ 142ms |
| Protocol Confusion (Multi-Layer) | ✅ 248ms | ✅ 146ms |
| State Table Exhaustion | ✅ 2166ms | ✅ 2103ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 84ms | ✅ 123ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 118ms | ✅ 166ms |
| HTTP/2 Steganography | ✅ 139ms | ✅ 140ms |
| WebSocket Salamander | ✅ 127ms | ✅ 140ms |
| Traffic Morph (Yandex Video) | ✅ 124ms | ✅ 138ms |
| Traffic Morph (VK Video) | ✅ 115ms | ✅ 171ms |
| Traffic Morph (Baidu Video) | ✅ 114ms | ✅ 172ms |
| Traffic Morph (Aparat Video) | ✅ 118ms | ✅ 171ms |
| Geneva (Russia TSPU) | ✅ 116ms | ✅ 166ms |
| Geneva (China GFW) | ✅ 136ms | ✅ 145ms |
| Geneva (Iran DPI) | ✅ 150ms | ✅ 139ms |
| Anti-Probe Resistance | ✅ 875ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 88ms | ✅ 118ms |
| Protocol Confusion (HTTP/TLS) | ✅ 89ms | ✅ 113ms |
| Protocol Confusion (SSH/TLS) | ✅ 94ms | ✅ 99ms |
| Protocol Confusion (SMTP/TLS) | ✅ 81ms | ✅ 112ms |
| Protocol Confusion (Multi-Layer) | ✅ 88ms | ✅ 109ms |
| State Table Exhaustion | ✅ 2081ms | ❌ — |

---
*Generated automatically.*
