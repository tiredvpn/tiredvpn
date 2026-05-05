# TiredVPN Availability Report — 2026-05-05

**Date:** 2026-05-05  |  **Version:** test

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 17 | 2 | quic_salamander | 269ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_0 | 79ms |
| MegaFon → Hetzner Amsterdam | 17 | 2 | confusion_0 | 121ms |
| MegaFon → Hetzner Nuremberg | 15 | 4 | confusion_1 | 106ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 269ms | ✅ 139ms |
| REALITY Protocol | ✅ 404ms | ✅ 205ms |
| HTTP Polling (meek-style) | ✅ 314ms | ✅ 185ms |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ❌ — | ❌ — |
| Traffic Morph (Yandex Video) | ✅ 1092ms | ✅ 969ms |
| Traffic Morph (VK Video) | ✅ 1080ms | ✅ 964ms |
| Traffic Morph (Baidu Video) | ✅ 1080ms | ✅ 970ms |
| Traffic Morph (Aparat Video) | ✅ 1079ms | ✅ 963ms |
| Geneva (Russia TSPU) | ✅ 320ms | ✅ 172ms |
| Geneva (China GFW) | ✅ 309ms | ✅ 186ms |
| Geneva (Iran DPI) | ✅ 358ms | ✅ 173ms |
| Anti-Probe Resistance | ✅ 1083ms | ✅ 943ms |
| Protocol Confusion (DNS/TLS) | ✅ 283ms | ✅ 121ms |
| Protocol Confusion (HTTP/TLS) | ✅ 280ms | ✅ 139ms |
| Protocol Confusion (SSH/TLS) | ✅ 284ms | ✅ 133ms |
| Protocol Confusion (SMTP/TLS) | ✅ 284ms | ✅ 133ms |
| Protocol Confusion (Multi-Layer) | ✅ 286ms | ✅ 122ms |
| State Table Exhaustion | ✅ 2082ms | ✅ 2099ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 92ms | ✅ 114ms |
| REALITY Protocol | ✅ 170ms | ✅ 183ms |
| HTTP Polling (meek-style) | ✅ 122ms | ✅ 142ms |
| HTTP/2 Steganography | ✅ 123ms | ✅ 145ms |
| WebSocket Salamander | ✅ 139ms | ✅ 144ms |
| Traffic Morph (Yandex Video) | ❌ — | ❌ — |
| Traffic Morph (VK Video) | ❌ — | ❌ — |
| Traffic Morph (Baidu Video) | ❌ — | ❌ — |
| Traffic Morph (Aparat Video) | ❌ — | ❌ — |
| Geneva (Russia TSPU) | ✅ 168ms | ✅ 170ms |
| Geneva (China GFW) | ✅ 121ms | ✅ 166ms |
| Geneva (Iran DPI) | ✅ 125ms | ✅ 173ms |
| Anti-Probe Resistance | ✅ 881ms | ✅ 906ms |
| Protocol Confusion (DNS/TLS) | ✅ 79ms | ✅ 110ms |
| Protocol Confusion (HTTP/TLS) | ✅ 85ms | ✅ 106ms |
| Protocol Confusion (SSH/TLS) | ✅ 82ms | ✅ 106ms |
| Protocol Confusion (SMTP/TLS) | ✅ 79ms | ✅ 123ms |
| Protocol Confusion (Multi-Layer) | ✅ 80ms | ✅ 107ms |
| State Table Exhaustion | ✅ 2081ms | ✅ 2099ms |

---
*Generated automatically.*
