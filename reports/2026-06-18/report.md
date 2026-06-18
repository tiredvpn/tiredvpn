# TiredVPN Availability Report — 2026-06-18

**Date:** 2026-06-18  |  **Version:** 1.1.3

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 16 | 3 | confusion_4 | 118ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_0 | 84ms |
| MegaFon → Hetzner Amsterdam | 15 | 4 | confusion_1 | 527ms |
| MegaFon → Hetzner Nuremberg | 8 | 11 | confusion_3 | 352ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ❌ — | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ❌ — | ❌ — |
| HTTP/2 Steganography | ✅ 213ms | ✅ 863ms |
| WebSocket Salamander | ✅ 165ms | ✅ 797ms |
| Traffic Morph (Yandex Video) | ✅ 144ms | ✅ 809ms |
| Traffic Morph (VK Video) | ✅ 163ms | ✅ 796ms |
| Traffic Morph (Baidu Video) | ✅ 149ms | ✅ 832ms |
| Traffic Morph (Aparat Video) | ✅ 145ms | ✅ 809ms |
| Geneva (Russia TSPU) | ✅ 185ms | ✅ 783ms |
| Geneva (China GFW) | ✅ 189ms | ✅ 862ms |
| Geneva (Iran DPI) | ✅ 186ms | ❌ — |
| Anti-Probe Resistance | ✅ 931ms | ✅ 1508ms |
| Protocol Confusion (DNS/TLS) | ✅ 135ms | ✅ 566ms |
| Protocol Confusion (HTTP/TLS) | ✅ 146ms | ✅ 527ms |
| Protocol Confusion (SSH/TLS) | ✅ 119ms | ✅ 572ms |
| Protocol Confusion (SMTP/TLS) | ✅ 142ms | ✅ 620ms |
| Protocol Confusion (Multi-Layer) | ✅ 118ms | ✅ 663ms |
| State Table Exhaustion | ✅ 2097ms | ✅ 2173ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ❌ — | ❌ — |
| REALITY Protocol | ❌ — | ❌ — |
| HTTP Polling (meek-style) | ❌ — | ❌ — |
| HTTP/2 Steganography | ❌ — | ❌ — |
| WebSocket Salamander | ✅ 134ms | ✅ 446ms |
| Traffic Morph (Yandex Video) | ✅ 144ms | ❌ — |
| Traffic Morph (VK Video) | ✅ 128ms | ✅ 426ms |
| Traffic Morph (Baidu Video) | ✅ 127ms | ❌ — |
| Traffic Morph (Aparat Video) | ✅ 121ms | ✅ 446ms |
| Geneva (Russia TSPU) | ✅ 151ms | ✅ 446ms |
| Geneva (China GFW) | ✅ 125ms | ✅ 446ms |
| Geneva (Iran DPI) | ✅ 132ms | ❌ — |
| Anti-Probe Resistance | ✅ 878ms | ❌ — |
| Protocol Confusion (DNS/TLS) | ✅ 84ms | ✅ 381ms |
| Protocol Confusion (HTTP/TLS) | ✅ 98ms | ❌ — |
| Protocol Confusion (SSH/TLS) | ✅ 86ms | ❌ — |
| Protocol Confusion (SMTP/TLS) | ✅ 87ms | ✅ 352ms |
| Protocol Confusion (Multi-Layer) | ✅ 94ms | ✅ 381ms |
| State Table Exhaustion | ✅ 2080ms | ❌ — |

---
*Generated automatically.*
