package geneva

// Pre-discovered Geneva strategies for various censorship systems
// Based on academic research and real-world testing

// ChinaGFWStrategy1 - Effective against China's GFW
// Strategy: "[TCP:flags:S]-duplicate(tamper{TTL:10})-|"
// Description: Duplicate SYN packets with low TTL to exhaust middlebox state
func ChinaGFWStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "China GFW Strategy 1",
			"description": "Duplicate SYN with low TTL",
			"success_rate": "75%",
		},
	}

	// Outbound: duplicate packet and tamper TTL on duplicate
	tamperTTL := NewTamperPrimitive("ttl", uint8(10))
	dupTamper := NewActionTree(NewDuplicatePrimitive(1), tamperTTL)

	return NewStrategy(trigger, dupTamper, nil)
}

// ChinaGFWStrategy2 - Alternative GFW bypass
// Strategy: "[TCP:flags:S]-tamper{flags:SA}-duplicate-|"
// Description: Send fake SYN-ACK before real SYN to confuse DPI
func ChinaGFWStrategy2() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "China GFW Strategy 2",
			"description": "Fake SYN-ACK confusion",
			"success_rate": "70%",
		},
	}

	// Outbound: tamper flags to SYN-ACK, then duplicate
	tamperFlags := NewTamperPrimitive("flags", uint8(TCPFlagSYN|TCPFlagACK))
	dup := NewDuplicatePrimitive(1)
	outbound := NewActionTree(tamperFlags, dup)

	return NewStrategy(trigger, outbound, nil)
}

// ChinaGFWStrategy3 - Fragment-based evasion
// Strategy: "[TCP:flags:PA]-fragment{offset:2}-|"
// Description: Fragment PSH-ACK packets to evade keyword detection
func ChinaGFWStrategy3() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "China GFW Strategy 3",
			"description": "Fragment PSH-ACK packets",
			"success_rate": "80%",
		},
	}

	// Outbound: fragment payload at offset 2
	frag := NewFragmentPrimitive(2, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// IranDPIStrategy1 - Effective against Iranian DPI
// Strategy: "[TCP:flags:S]-tamper{seq:10000}-duplicate-|"
// Description: Tamper sequence number on duplicate to desync DPI
func IranDPIStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Iran DPI Strategy 1",
			"description": "Sequence number tampering",
			"success_rate": "65%",
		},
	}

	// Outbound: tamper seq, then duplicate
	tamperSeq := NewTamperPrimitive("seq", uint32(10000))
	dup := NewDuplicatePrimitive(1)
	outbound := NewActionTree(tamperSeq, dup)

	return NewStrategy(trigger, outbound, nil)
}

// IranDPIStrategy2 - Alternative Iranian bypass
// Strategy: "[TCP:flags:PA]-fragment{offset:8}-|"
// Description: Fragment HTTP requests to evade content filtering
func IranDPIStrategy2() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Iran DPI Strategy 2",
			"description": "Fragment HTTP requests",
			"success_rate": "70%",
		},
	}

	// Outbound: fragment at offset 8 (after "GET / HT")
	frag := NewFragmentPrimitive(8, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// RussiaTSPUStrategy1 - Effective against Russian TSPU DPI
// Strategy: "[TCP:flags:S]-duplicate(tamper{TTL:8})-|"
// Description: Low TTL duplicate to exhaust TSPU state tracking
func RussiaTSPUStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Russia TSPU Strategy 1",
			"description": "Low TTL SYN duplicate",
			"success_rate": "85%",
		},
	}

	// Outbound: duplicate with TTL=8
	tamperTTL := NewTamperPrimitive("ttl", uint8(8))
	dup := NewDuplicatePrimitive(1)
	outbound := NewActionTree(dup, tamperTTL)

	return NewStrategy(trigger, outbound, nil)
}

// RussiaTSPUStrategy2 - Alternative TSPU bypass
// Strategy: "[TCP:flags:PA]-fragment{offset:1}-|"
// Description: Fragment at offset 1 to break SNI detection
func RussiaTSPUStrategy2() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Russia TSPU Strategy 2",
			"description": "Single-byte fragment for SNI evasion",
			"success_rate": "90%",
		},
	}

	// Outbound: fragment at offset 1
	frag := NewFragmentPrimitive(1, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// RussiaTSPUStrategy3 - Advanced TSPU bypass
// Strategy: "[TCP:flags:PA]-duplicate(tamper{flags:R})-|"
// Description: Send RST duplicate to poison TSPU flow table
func RussiaTSPUStrategy3() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Russia TSPU Strategy 3",
			"description": "RST poisoning",
			"success_rate": "80%",
		},
	}

	// Outbound: duplicate packet with RST flag
	tamperFlags := NewTamperPrimitive("flags", uint8(TCPFlagRST))
	dup := NewDuplicatePrimitive(1)
	outbound := NewActionTree(dup, tamperFlags)

	return NewStrategy(trigger, outbound, nil)
}

// TurkeyDPIStrategy1 - Effective against Turkish DPI
// Strategy: "[TCP:flags:S]-duplicate(tamper{seq:0})-|"
// Description: Zero sequence number on duplicate to confuse DPI
func TurkeyDPIStrategy1() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Turkey DPI Strategy 1",
			"description": "Zero sequence number confusion",
			"success_rate": "60%",
		},
	}

	// Outbound: tamper seq to 0, then duplicate
	tamperSeq := NewTamperPrimitive("seq", uint32(0))
	dup := NewDuplicatePrimitive(1)
	outbound := NewActionTree(tamperSeq, dup)

	return NewStrategy(trigger, outbound, nil)
}

// GenericFragmentStrategy - Generic fragmentation bypass
// Strategy: "[TCP:flags:PA]-fragment{offset:10}-|"
// Description: Fragment payload to evade basic keyword detection
func GenericFragmentStrategy() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagPSH | TCPFlagACK),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Generic Fragment Strategy",
			"description": "Basic payload fragmentation",
			"success_rate": "50%",
		},
	}

	// Outbound: fragment at offset 10
	frag := NewFragmentPrimitive(10, 0)
	outbound := NewActionTree(frag)

	return NewStrategy(trigger, outbound, nil)
}

// GenericDuplicateStrategy - Generic duplicate bypass
// Strategy: "[TCP:flags:S]-duplicate-|"
// Description: Simple SYN duplication to exhaust middlebox resources
func GenericDuplicateStrategy() *Strategy {
	trigger := Trigger{
		Protocol: "TCP",
		Field:    "flags",
		Value:    uint8(TCPFlagSYN),
		Operator: "&",
		Metadata: map[string]string{
			"name":        "Generic Duplicate Strategy",
			"description": "Simple SYN duplication",
			"success_rate": "40%",
		},
	}

	// Outbound: duplicate packet
	dup := NewDuplicatePrimitive(1)
	outbound := NewActionTree(dup)

	return NewStrategy(trigger, outbound, nil)
}

// GetAllStrategies returns all pre-discovered Geneva strategies
func GetAllStrategies() map[string]*Strategy {
	return map[string]*Strategy{
		"china_gfw_1":     ChinaGFWStrategy1(),
		"china_gfw_2":     ChinaGFWStrategy2(),
		"china_gfw_3":     ChinaGFWStrategy3(),
		"iran_dpi_1":      IranDPIStrategy1(),
		"iran_dpi_2":      IranDPIStrategy2(),
		"russia_tspu_1":   RussiaTSPUStrategy1(),
		"russia_tspu_2":   RussiaTSPUStrategy2(),
		"russia_tspu_3":   RussiaTSPUStrategy3(),
		"turkey_dpi_1":    TurkeyDPIStrategy1(),
		"generic_fragment": GenericFragmentStrategy(),
		"generic_dup":     GenericDuplicateStrategy(),
	}
}

// GetStrategyByName returns a specific strategy by name
func GetStrategyByName(name string) *Strategy {
	strategies := GetAllStrategies()
	return strategies[name]
}

// GetStrategiesByCountry returns strategies for a specific country
func GetStrategiesByCountry(country string) []*Strategy {
	all := GetAllStrategies()
	var result []*Strategy

	switch country {
	case "china", "cn":
		result = append(result,
			all["china_gfw_1"],
			all["china_gfw_2"],
			all["china_gfw_3"],
		)
	case "iran", "ir":
		result = append(result,
			all["iran_dpi_1"],
			all["iran_dpi_2"],
		)
	case "russia", "ru":
		result = append(result,
			all["russia_tspu_1"],
			all["russia_tspu_2"],
			all["russia_tspu_3"],
		)
	case "turkey", "tr":
		result = append(result, all["turkey_dpi_1"])
	default:
		// Return generic strategies
		result = append(result,
			all["generic_fragment"],
			all["generic_dup"],
		)
	}

	return result
}

// GetSuccessRate returns the estimated success rate for a strategy
func (s *Strategy) GetSuccessRate() string {
	if s.Trigger.Metadata != nil {
		return s.Trigger.Metadata["success_rate"]
	}
	return "unknown"
}

// GetName returns the strategy name
func (s *Strategy) GetName() string {
	if s.Trigger.Metadata != nil {
		return s.Trigger.Metadata["name"]
	}
	return "unnamed strategy"
}

// GetDescription returns the strategy description
func (s *Strategy) GetDescription() string {
	if s.Trigger.Metadata != nil {
		return s.Trigger.Metadata["description"]
	}
	return "no description"
}
