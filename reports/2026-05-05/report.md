# TiredVPN Availability Report — 2026-05-05

**Date:** 2026-05-05  |  **Version:** test

## Summary

| Client ISP → Server | OK | Blocked | Best strategy | Best latency |
|---------------------|----|---------|--------------:|-------------|
| Rostelecom → Hetzner Amsterdam | 17 | 2 | quic_salamander | 105ms |
| Rostelecom → Hetzner Nuremberg | 15 | 4 | confusion_3 | 80ms |

## Strategy Results

| Strategy | → Hetzner Amsterdam | → Hetzner Nuremberg |
|----------|---------------------|---------------------|
| QUIC Salamander | ✅ 105ms    | ✅ 85ms     |
| REALITY Protocol | ✅ 280ms    | ✅ 173ms    |
| HTTP Polling (meek-style) | ✅ 142ms    | ✅ 128ms    |
| HTTP/2 Steganography | ❌ —        | ✅ 121ms    |
| WebSocket Salamander | ❌ —        | ✅ 125ms    |
| Traffic Morph (Yandex Video) | ✅ 972ms    | ❌ —        |
| Traffic Morph (VK Video) | ✅ 973ms    | ❌ —        |
| Traffic Morph (Baidu Video) | ✅ 989ms    | ❌ —        |
| Traffic Morph (Aparat Video) | ✅ 989ms    | ❌ —        |
| Geneva (Russia TSPU) | ✅ 133ms    | ✅ 121ms    |
| Geneva (China GFW) | ✅ 153ms    | ✅ 126ms    |
| Geneva (Iran DPI) | ✅ 155ms    | ✅ 129ms    |
| Anti-Probe Resistance | ✅ 960ms    | ✅ 887ms    |
| Protocol Confusion (DNS/TLS) | ✅ 117ms    | ✅ 93ms     |
| Protocol Confusion (HTTP/TLS) | ✅ 114ms    | ✅ 82ms     |
| Protocol Confusion (SSH/TLS) | ✅ 111ms    | ✅ 92ms     |
| Protocol Confusion (SMTP/TLS) | ✅ 115ms    | ✅ 80ms     |
| Protocol Confusion (Multi-Layer) | ✅ 108ms    | ✅ 81ms     |
| State Table Exhaustion | ✅ 2100ms   | ✅ 2079ms   |

---
*Generated automatically.*
