# TiredVPN Availability Report — 2026-05-05

**Date:** 2026-05-05  |  **Version:** 1.1.1

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 18 | 1 | confusion_2 | 93ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_3 | 78ms |
| MegaFon → Hetzner Amsterdam | 18 | 1 | confusion_2 | 125ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 111ms | ✅ 130ms |
| REALITY Protocol | ✅ 194ms | ✅ 224ms |
| HTTP Polling (meek-style) | ✅ 152ms | ✅ 179ms |
| HTTP/2 Steganography | ❌ — | ✅ 168ms |
| WebSocket Salamander | ✅ 135ms | ❌ — |
| Traffic Morph (Yandex Video) | ✅ 943ms | ✅ 968ms |
| Traffic Morph (VK Video) | ✅ 950ms | ✅ 967ms |
| Traffic Morph (Baidu Video) | ✅ 955ms | ✅ 964ms |
| Traffic Morph (Aparat Video) | ✅ 945ms | ✅ 968ms |
| Geneva (Russia TSPU) | ✅ 176ms | ✅ 167ms |
| Geneva (China GFW) | ✅ 147ms | ✅ 179ms |
| Geneva (Iran DPI) | ✅ 138ms | ✅ 177ms |
| Anti-Probe Resistance | ✅ 912ms | ✅ 935ms |
| Protocol Confusion (DNS/TLS) | ✅ 102ms | ✅ 126ms |
| Protocol Confusion (HTTP/TLS) | ✅ 98ms | ✅ 131ms |
| Protocol Confusion (SSH/TLS) | ✅ 93ms | ✅ 125ms |
| Protocol Confusion (SMTP/TLS) | ✅ 100ms | ✅ 126ms |
| Protocol Confusion (Multi-Layer) | ✅ 113ms | ✅ 130ms |
| State Table Exhaustion | ✅ 2086ms | ✅ 2094ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ✅ 80ms |
| REALITY Protocol | ✅ 171ms |
| HTTP Polling (meek-style) | ✅ 116ms |
| HTTP/2 Steganography | ✅ 118ms |
| WebSocket Salamander | ✅ 127ms |
| Traffic Morph (Yandex Video) | ❌ — |
| Traffic Morph (VK Video) | ❌ — |
| Traffic Morph (Baidu Video) | ❌ — |
| Traffic Morph (Aparat Video) | ❌ — |
| Geneva (Russia TSPU) | ✅ 127ms |
| Geneva (China GFW) | ✅ 153ms |
| Geneva (Iran DPI) | ✅ 117ms |
| Anti-Probe Resistance | ✅ 882ms |
| Protocol Confusion (DNS/TLS) | ✅ 83ms |
| Protocol Confusion (HTTP/TLS) | ✅ 82ms |
| Protocol Confusion (SSH/TLS) | ✅ 79ms |
| Protocol Confusion (SMTP/TLS) | ✅ 78ms |
| Protocol Confusion (Multi-Layer) | ✅ 82ms |
| State Table Exhaustion | ✅ 2078ms |

---
*Generated automatically.*
