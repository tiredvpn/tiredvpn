# TiredVPN Availability Report — 2026-05-27

**Date:** 2026-05-27  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_1 | 95ms |
| Rostelecom → Hetzner Nuremberg | 18 | 1 | confusion_1 | 77ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 113ms |
| MegaFon → Hetzner Nuremberg | 11 | 8 | confusion_4 | 105ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 112ms | ✅ 128ms |
| REALITY Protocol | ✅ 193ms | ✅ 218ms |
| HTTP Polling (meek-style) | ✅ 149ms | ✅ 172ms |
| HTTP/2 Steganography | ✅ 137ms | ✅ 177ms |
| WebSocket Salamander | ✅ 160ms | ✅ 177ms |
| Traffic Morph (Yandex Video) | ✅ 138ms | ✅ 164ms |
| Traffic Morph (VK Video) | ✅ 131ms | ✅ 177ms |
| Traffic Morph (Baidu Video) | ✅ 130ms | ✅ 166ms |
| Traffic Morph (Aparat Video) | ✅ 126ms | ✅ 171ms |
| Geneva (Russia TSPU) | ✅ 171ms | ✅ 160ms |
| Geneva (China GFW) | ✅ 155ms | ✅ 176ms |
| Geneva (Iran DPI) | ✅ 143ms | ✅ 177ms |
| Anti-Probe Resistance | ✅ 909ms | ✅ 932ms |
| Protocol Confusion (DNS/TLS) | ✅ 100ms | ✅ 113ms |
| Protocol Confusion (HTTP/TLS) | ✅ 95ms | ✅ 122ms |
| Protocol Confusion (SSH/TLS) | ✅ 112ms | ✅ 123ms |
| Protocol Confusion (SMTP/TLS) | ✅ 103ms | ✅ 124ms |
| Protocol Confusion (Multi-Layer) | ✅ 100ms | ✅ 125ms |
| State Table Exhaustion | ✅ 2089ms | ✅ 2106ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 89ms | ✅ 118ms |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ✅ 120ms | ✅ 163ms |
| HTTP/2 Steganography | ✅ 115ms | ✅ 154ms |
| WebSocket Salamander | ✅ 125ms | ✅ 144ms |
| Traffic Morph (Yandex Video) | ✅ 121ms | ❌ — |
| Traffic Morph (VK Video) | ✅ 117ms | ❌ — |
| Traffic Morph (Baidu Video) | ✅ 129ms | ❌ — |
| Traffic Morph (Aparat Video) | ✅ 124ms | ❌ — |
| Geneva (Russia TSPU) | ✅ 133ms | ✅ 167ms |
| Geneva (China GFW) | ✅ 156ms | ✅ 143ms |
| Geneva (Iran DPI) | ✅ 127ms | ✅ 164ms |
| Anti-Probe Resistance | ✅ 876ms | ✅ 904ms |
| Protocol Confusion (DNS/TLS) | ✅ 81ms | ❌ — |
| Protocol Confusion (HTTP/TLS) | ✅ 77ms | ✅ 108ms |
| Protocol Confusion (SSH/TLS) | ✅ 80ms | ✅ 117ms |
| Protocol Confusion (SMTP/TLS) | ✅ 82ms | ❌ — |
| Protocol Confusion (Multi-Layer) | ✅ 82ms | ✅ 105ms |
| State Table Exhaustion | ✅ 2080ms | ❌ — |

---
*Generated automatically.*
