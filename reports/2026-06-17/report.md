# TiredVPN Availability Report — 2026-06-17

**Date:** 2026-06-17  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_1 | 111ms |
| Rostelecom → Hetzner Nuremberg | 16 | 3 | confusion_4 | 79ms |
| MegaFon → Hetzner Amsterdam | 15 | 4 | confusion_1 | 667ms |
| MegaFon → Hetzner Nuremberg | 13 | 6 | confusion_0 | 266ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ❌ — | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ❌ — | ❌ — |
| HTTP/2 Steganography | ✅ 179ms | ✅ 937ms |
| WebSocket Salamander | ✅ 222ms | ✅ 937ms |
| Traffic Morph (Yandex Video) | ✅ 156ms | ✅ 901ms |
| Traffic Morph (VK Video) | ✅ 154ms | ✅ 973ms |
| Traffic Morph (Baidu Video) | ✅ 157ms | ✅ 979ms |
| Traffic Morph (Aparat Video) | ✅ 151ms | ✅ 979ms |
| Geneva (Russia TSPU) | ✅ 180ms | ✅ 972ms |
| Geneva (China GFW) | ✅ 171ms | ✅ 942ms |
| Geneva (Iran DPI) | ✅ 220ms | ❌ — |
| Anti-Probe Resistance | ✅ 945ms | ✅ 1626ms |
| Protocol Confusion (DNS/TLS) | ✅ 114ms | ✅ 883ms |
| Protocol Confusion (HTTP/TLS) | ✅ 111ms | ✅ 667ms |
| Protocol Confusion (SSH/TLS) | ✅ 116ms | ✅ 703ms |
| Protocol Confusion (SMTP/TLS) | ✅ 143ms | ✅ 703ms |
| Protocol Confusion (Multi-Layer) | ✅ 146ms | ✅ 870ms |
| State Table Exhaustion | ✅ 2091ms | ✅ 2211ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ❌ — | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ❌ — | ❌ — |
| HTTP/2 Steganography | ✅ 127ms | ❌ — |
| WebSocket Salamander | ✅ 145ms | ✅ 535ms |
| Traffic Morph (Yandex Video) | ✅ 133ms | ✅ 548ms |
| Traffic Morph (VK Video) | ✅ 144ms | ✅ 548ms |
| Traffic Morph (Baidu Video) | ✅ 140ms | ✅ 560ms |
| Traffic Morph (Aparat Video) | ✅ 137ms | ✅ 566ms |
| Geneva (Russia TSPU) | ✅ 155ms | ✅ 572ms |
| Geneva (China GFW) | ✅ 120ms | ✅ 572ms |
| Geneva (Iran DPI) | ✅ 128ms | ❌ — |
| Anti-Probe Resistance | ✅ 891ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 90ms | ✅ 266ms |
| Protocol Confusion (HTTP/TLS) | ✅ 80ms | ✅ 333ms |
| Protocol Confusion (SSH/TLS) | ✅ 86ms | ✅ 333ms |
| Protocol Confusion (SMTP/TLS) | ✅ 87ms | ✅ 333ms |
| Protocol Confusion (Multi-Layer) | ✅ 79ms | ✅ 447ms |
| State Table Exhaustion | ✅ 2095ms | ✅ 2189ms |

---
*Generated automatically.*
