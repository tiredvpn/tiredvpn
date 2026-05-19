# TiredVPN Availability Report — 2026-05-19

**Date:** 2026-05-19  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_1 | 89ms |
| Rostelecom → Hetzner Nuremberg | 17 | 2 | confusion_4 | 81ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 231ms |
| MegaFon → Hetzner Nuremberg | 17 | 2 | confusion_3 | 108ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 112ms | ✅ 274ms |
| REALITY Protocol | ✅ 194ms | ✅ 515ms |
| HTTP Polling (meek-style) | ✅ 129ms | ✅ 295ms |
| HTTP/2 Steganography | ✅ 149ms | ✅ 468ms |
| WebSocket Salamander | ✅ 155ms | ✅ 299ms |
| Traffic Morph (Yandex Video) | ✅ 135ms | ✅ 287ms |
| Traffic Morph (VK Video) | ✅ 128ms | ✅ 291ms |
| Traffic Morph (Baidu Video) | ✅ 121ms | ✅ 287ms |
| Traffic Morph (Aparat Video) | ✅ 125ms | ✅ 287ms |
| Geneva (Russia TSPU) | ✅ 189ms | ✅ 469ms |
| Geneva (China GFW) | ✅ 149ms | ✅ 468ms |
| Geneva (Iran DPI) | ✅ 124ms | ✅ 460ms |
| Anti-Probe Resistance | ✅ 910ms | ✅ 1072ms |
| Protocol Confusion (DNS/TLS) | ✅ 94ms | ✅ 231ms |
| Protocol Confusion (HTTP/TLS) | ✅ 89ms | ✅ 257ms |
| Protocol Confusion (SSH/TLS) | ✅ 104ms | ✅ 236ms |
| Protocol Confusion (SMTP/TLS) | ✅ 109ms | ✅ 240ms |
| Protocol Confusion (Multi-Layer) | ✅ 108ms | ✅ 231ms |
| State Table Exhaustion | ✅ 2086ms | ✅ 2123ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 93ms | ✅ 120ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 120ms | ✅ 137ms |
| HTTP/2 Steganography | ✅ 133ms | ✅ 174ms |
| WebSocket Salamander | ✅ 127ms | ✅ 164ms |
| Traffic Morph (Yandex Video) | ✅ 124ms | ✅ 146ms |
| Traffic Morph (VK Video) | ✅ 123ms | ✅ 170ms |
| Traffic Morph (Baidu Video) | ✅ 120ms | ✅ 138ms |
| Traffic Morph (Aparat Video) | ✅ 131ms | ✅ 144ms |
| Geneva (Russia TSPU) | ✅ 182ms | ✅ 167ms |
| Geneva (China GFW) | ✅ 143ms | ✅ 164ms |
| Geneva (Iran DPI) | ✅ 118ms | ✅ 162ms |
| Anti-Probe Resistance | ❌ — | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 86ms | ✅ 125ms |
| Protocol Confusion (HTTP/TLS) | ✅ 98ms | ✅ 124ms |
| Protocol Confusion (SSH/TLS) | ✅ 87ms | ✅ 119ms |
| Protocol Confusion (SMTP/TLS) | ✅ 86ms | ✅ 108ms |
| Protocol Confusion (Multi-Layer) | ✅ 81ms | ✅ 118ms |
| State Table Exhaustion | ✅ 2091ms | ✅ 2116ms |

---
*Generated automatically.*
