# TiredVPN Availability Report — 2026-05-06

**Date:** 2026-05-06  |  **Version:** 1.1.2

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 17 | 2 | confusion_1 | 102ms |
| Rostelecom → Hetzner Nuremberg | 19 | 0 | confusion_1 | 82ms |
| MegaFon → Hetzner Amsterdam | 17 | 2 | confusion_3 | 145ms |
| MegaFon → Hetzner Nuremberg | 19 | 0 | confusion_2 | 103ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 111ms | ✅ 165ms |
| REALITY Protocol | ✅ 191ms | ✅ 245ms |
| HTTP Polling (meek-style) | ✅ 159ms | ✅ 209ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ❌ — | ❌ — |
| Traffic Morph (Yandex Video) | ✅ 133ms | ✅ 184ms |
| Traffic Morph (VK Video) | ✅ 137ms | ✅ 188ms |
| Traffic Morph (Baidu Video) | ✅ 140ms | ✅ 183ms |
| Traffic Morph (Aparat Video) | ✅ 178ms | ✅ 187ms |
| Geneva (Russia TSPU) | ✅ 194ms | ✅ 202ms |
| Geneva (China GFW) | ✅ 178ms | ✅ 196ms |
| Geneva (Iran DPI) | ✅ 156ms | ✅ 216ms |
| Anti-Probe Resistance | ✅ 947ms | ✅ 953ms |
| Protocol Confusion (DNS/TLS) | ✅ 115ms | ✅ 149ms |
| Protocol Confusion (HTTP/TLS) | ✅ 102ms | ✅ 156ms |
| Protocol Confusion (SSH/TLS) | ✅ 108ms | ✅ 160ms |
| Protocol Confusion (SMTP/TLS) | ✅ 114ms | ✅ 145ms |
| Protocol Confusion (Multi-Layer) | ✅ 107ms | ✅ 156ms |
| State Table Exhaustion | ✅ 2102ms | ✅ 2116ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 93ms | ✅ 110ms |
| REALITY Protocol | ✅ 166ms | ✅ 194ms |
| HTTP Polling (meek-style) | ✅ 131ms | ✅ 171ms |
| HTTP/2 Steganography | ✅ 127ms | ✅ 168ms |
| WebSocket Salamander | ✅ 126ms | ✅ 139ms |
| Traffic Morph (Yandex Video) | ✅ 125ms | ✅ 137ms |
| Traffic Morph (VK Video) | ✅ 133ms | ✅ 144ms |
| Traffic Morph (Baidu Video) | ✅ 128ms | ✅ 170ms |
| Traffic Morph (Aparat Video) | ✅ 123ms | ✅ 170ms |
| Geneva (Russia TSPU) | ✅ 165ms | ✅ 166ms |
| Geneva (China GFW) | ✅ 123ms | ✅ 166ms |
| Geneva (Iran DPI) | ✅ 134ms | ✅ 168ms |
| Anti-Probe Resistance | ✅ 879ms | ✅ 917ms |
| Protocol Confusion (DNS/TLS) | ✅ 83ms | ✅ 112ms |
| Protocol Confusion (HTTP/TLS) | ✅ 82ms | ✅ 112ms |
| Protocol Confusion (SSH/TLS) | ✅ 84ms | ✅ 103ms |
| Protocol Confusion (SMTP/TLS) | ✅ 84ms | ✅ 114ms |
| Protocol Confusion (Multi-Layer) | ✅ 90ms | ✅ 119ms |
| State Table Exhaustion | ✅ 2083ms | ✅ 2081ms |

---
*Generated automatically.*
