package client

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type AndroidMetrics struct {
	// VpnService protect() calls
	protectCalls uint64

	// Network type (0=unknown, 1=wifi, 2=cellular)
	networkType uint64

	// Battery level (0-100)
	batteryLevel uint64
}

func NewAndroidMetrics() *AndroidMetrics {
	return &AndroidMetrics{}
}

func (am *AndroidMetrics) RecordProtectCall() {
	atomic.AddUint64(&am.protectCalls, 1)
}

func (am *AndroidMetrics) SetNetworkType(netType string) {
	var typeVal uint64
	switch netType {
	case "wifi":
		typeVal = 1
	case "cellular":
		typeVal = 2
	default:
		typeVal = 0 // unknown
	}
	atomic.StoreUint64(&am.networkType, typeVal)
}

func (am *AndroidMetrics) UpdateBatteryLevel(level int) {
	if level < 0 {
		level = 0
	}
	if level > 100 {
		level = 100
	}
	atomic.StoreUint64(&am.batteryLevel, uint64(level))
}

func (am *AndroidMetrics) ExportPrometheus(w http.ResponseWriter) {
	// Protect calls
	fmt.Fprintf(w, "# HELP tiredvpn_local_android_protect_calls_total VpnService protect() calls\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_android_protect_calls_total counter\n")
	fmt.Fprintf(w, "tiredvpn_local_android_protect_calls_total %d\n", atomic.LoadUint64(&am.protectCalls))
	fmt.Fprintf(w, "\n")

	// Network type
	netType := atomic.LoadUint64(&am.networkType)
	var netTypeStr string
	switch netType {
	case 1:
		netTypeStr = "wifi"
	case 2:
		netTypeStr = "cellular"
	default:
		netTypeStr = "unknown"
	}

	fmt.Fprintf(w, "# HELP tiredvpn_local_android_network_type Android network type\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_android_network_type gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_android_network_type{type=\"%s\"} 1\n", netTypeStr)
	fmt.Fprintf(w, "\n")

	// Battery level
	fmt.Fprintf(w, "# HELP tiredvpn_local_android_battery_level_percent Battery level\n")
	fmt.Fprintf(w, "# TYPE tiredvpn_local_android_battery_level_percent gauge\n")
	fmt.Fprintf(w, "tiredvpn_local_android_battery_level_percent %d\n", atomic.LoadUint64(&am.batteryLevel))
	fmt.Fprintf(w, "\n")
}
