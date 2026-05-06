# TiredVPN Availability Report — 2026-05-06

**Date:** 2026-05-06  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_3 | 90ms |
| Rostelecom → Hetzner Nuremberg | 19 | 0 | confusion_3 | 80ms |
| MegaFon → Hetzner Amsterdam | 19 | 0 | confusion_0 | 105ms |
| MegaFon → Hetzner Nuremberg | 19 | 0 | confusion_2 | 104ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 140ms | ✅ 132ms |
| REALITY Protocol | ✅ 231ms | ✅ 217ms |
| HTTP Polling (meek-style) | ✅ 175ms | ✅ 172ms |
| HTTP/2 Steganography | ✅ 139ms | ✅ 179ms |
| WebSocket Salamander | ✅ 140ms | ✅ 177ms |
| Traffic Morph (Yandex Video) | ✅ 135ms | ✅ 172ms |
| Traffic Morph (VK Video) | ✅ 137ms | ✅ 172ms |
| Traffic Morph (Baidu Video) | ✅ 177ms | ✅ 171ms |
| Traffic Morph (Aparat Video) | ✅ 137ms | ✅ 179ms |
| Geneva (Russia TSPU) | ✅ 185ms | ✅ 166ms |
| Geneva (China GFW) | ✅ 170ms | ✅ 182ms |
| Geneva (Iran DPI) | ✅ 189ms | ✅ 182ms |
| Anti-Probe Resistance | ✅ 888ms | ✅ 906ms |
| Protocol Confusion (DNS/TLS) | ✅ 121ms | ✅ 105ms |
| Protocol Confusion (HTTP/TLS) | ✅ 123ms | ✅ 120ms |
| Protocol Confusion (SSH/TLS) | ✅ 134ms | ✅ 119ms |
| Protocol Confusion (SMTP/TLS) | ✅ 90ms | ✅ 126ms |
| Protocol Confusion (Multi-Layer) | ✅ 92ms | ✅ 130ms |
| State Table Exhaustion | ✅ 2083ms | ✅ 2102ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 89ms | ✅ 121ms |
| REALITY Protocol | ✅ 162ms | ✅ 193ms |
| HTTP Polling (meek-style) | ✅ 115ms | ✅ 168ms |
| HTTP/2 Steganography | ✅ 135ms | ✅ 171ms |
| WebSocket Salamander | ✅ 119ms | ✅ 170ms |
| Traffic Morph (Yandex Video) | ✅ 122ms | ✅ 146ms |
| Traffic Morph (VK Video) | ✅ 123ms | ✅ 171ms |
| Traffic Morph (Baidu Video) | ✅ 122ms | ✅ 169ms |
| Traffic Morph (Aparat Video) | ✅ 113ms | ✅ 145ms |
| Geneva (Russia TSPU) | ✅ 162ms | ✅ 145ms |
| Geneva (China GFW) | ✅ 131ms | ✅ 168ms |
| Geneva (Iran DPI) | ✅ 122ms | ✅ 170ms |
| Anti-Probe Resistance | ✅ 881ms | ✅ 911ms |
| Protocol Confusion (DNS/TLS) | ✅ 88ms | ✅ 120ms |
| Protocol Confusion (HTTP/TLS) | ✅ 81ms | ✅ 107ms |
| Protocol Confusion (SSH/TLS) | ✅ 87ms | ✅ 104ms |
| Protocol Confusion (SMTP/TLS) | ✅ 80ms | ✅ 106ms |
| Protocol Confusion (Multi-Layer) | ✅ 90ms | ✅ 112ms |
| State Table Exhaustion | ✅ 2083ms | ✅ 2099ms |

---
*Generated automatically.*
