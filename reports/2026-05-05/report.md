# TiredVPN Availability Report — 2026-05-05

**Date:** 2026-05-05  |  **Version:** test

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 19 | 0 | confusion_0 | 87ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_3 | 77ms |
| MegaFon → Hetzner Amsterdam | 17 | 2 | confusion_4 | 118ms |

## Strategy Results

### → Hetzner Amsterdam

| Strategy | Rostelecom | MegaFon |
|----------|------------|---------|
| QUIC Salamander | ✅ 97ms | ✅ 130ms |
| REALITY Protocol | ✅ 201ms | ✅ 223ms |
| HTTP Polling (meek-style) | ✅ 137ms | ✅ 185ms |
| HTTP/2 Steganography | ✅ 159ms | ❌ — |
| WebSocket Salamander | ✅ 148ms | ❌ — |
| Traffic Morph (Yandex Video) | ✅ 941ms | ✅ 970ms |
| Traffic Morph (VK Video) | ✅ 952ms | ✅ 966ms |
| Traffic Morph (Baidu Video) | ✅ 947ms | ✅ 981ms |
| Traffic Morph (Aparat Video) | ✅ 940ms | ✅ 963ms |
| Geneva (Russia TSPU) | ✅ 168ms | ✅ 181ms |
| Geneva (China GFW) | ✅ 165ms | ✅ 170ms |
| Geneva (Iran DPI) | ✅ 160ms | ✅ 176ms |
| Anti-Probe Resistance | ✅ 910ms | ✅ 946ms |
| Protocol Confusion (DNS/TLS) | ✅ 87ms | ✅ 121ms |
| Protocol Confusion (HTTP/TLS) | ✅ 93ms | ✅ 122ms |
| Protocol Confusion (SSH/TLS) | ✅ 101ms | ✅ 122ms |
| Protocol Confusion (SMTP/TLS) | ✅ 107ms | ✅ 128ms |
| Protocol Confusion (Multi-Layer) | ✅ 102ms | ✅ 118ms |
| State Table Exhaustion | ✅ 2086ms | ✅ 2094ms |

### → Hetzner Nuremberg

| Strategy | Rostelecom |
|----------|------------|
| QUIC Salamander | ✅ 88ms |
| REALITY Protocol | ✅ 167ms |
| HTTP Polling (meek-style) | ✅ 118ms |
| HTTP/2 Steganography | ✅ 117ms |
| WebSocket Salamander | ✅ 124ms |
| Traffic Morph (Yandex Video) | ❌ — |
| Traffic Morph (VK Video) | ❌ — |
| Traffic Morph (Baidu Video) | ❌ — |
| Traffic Morph (Aparat Video) | ❌ — |
| Geneva (Russia TSPU) | ✅ 117ms |
| Geneva (China GFW) | ✅ 125ms |
| Geneva (Iran DPI) | ✅ 122ms |
| Anti-Probe Resistance | ✅ 872ms |
| Protocol Confusion (DNS/TLS) | ✅ 84ms |
| Protocol Confusion (HTTP/TLS) | ✅ 89ms |
| Protocol Confusion (SSH/TLS) | ✅ 89ms |
| Protocol Confusion (SMTP/TLS) | ✅ 77ms |
| Protocol Confusion (Multi-Layer) | ✅ 83ms |
| State Table Exhaustion | ✅ 2079ms |

---
*Generated automatically.*
