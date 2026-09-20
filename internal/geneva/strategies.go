package geneva

// Pre-discovered Geneva strategies for various censorship systems
// Based on academic research and real-world testing

// decoyThenReal builds the tree every packet-level strategy here needs: one
// duplicate, the decoy manipulated, the real packet sent untouched.
//
// The chained form these strategies used before - NewActionTree(dup, tamper) -
// cannot express that. ActionNode.Execute applies each following primitive to
// every result of the one before, so the tamper hit the original as well as the
// copy: Russia TSPU 1 put TTL=8 on the real SYN, which then expired before
// reaching the server; TSPU 3 turned the real PSH-ACK into an RST; China GFW 2
// and Turkey 1 tampered first and duplicated afterwards, so the untouched
// packet was never sent at all. Branch routing is what keeps the two apart, see
// ActionTree.Execute.
//
// The decoy goes out first. The point of all of these is to put a packet in
// front of the middlebox before the real one arrives - a low-TTL SYN it
// processes and the server never sees, an RST that poisons its flow table, a
// SYN-ACK that desynchronises its state machine. Behind the real packet a decoy
// has nothing left to poison.
//
// Branch 0 receives the original and branch 1 the copy, but at this point the
// two are byte-identical, so tampering "the original" and tampering the copy
// are the same operation. What matters is that exactly one of the two is
// manipulated. TamperPrimitive.Apply writes into a fresh buffer, so the packet
// handed to Apply is never modified in place.
func decoyThenReal(decoy Primitive) *ActionTree {
	tree := NewActionTree(NewDuplicatePrimitive(1))
	tree.AddBranch(NewActionTree(decoy))            // result 0: the decoy
	tree.AddBranch(NewActionTree(&SendPrimitive{})) // result 1: the real packet
	return tree
}

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
		},
	}

	// Outbound: a low-TTL decoy SYN, then the real SYN untouched
	tamperTTL := NewTamperPrimitive("ttl", uint8(10))

	return NewStrategy(trigger, decoyThenReal(tamperTTL), nil)
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
		},
	}

	// Outbound: a fake SYN-ACK decoy, then the real SYN untouched
	tamperFlags := NewTamperPrimitive("flags", uint8(TCPFlagSYN|TCPFlagACK))

	return NewStrategy(trigger, decoyThenReal(tamperFlags), nil)
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
		},
	}

	// Outbound: a decoy with a desynchronising seq, then the real SYN untouched
	tamperSeq := NewTamperPrimitive("seq", uint32(10000))

	return NewStrategy(trigger, decoyThenReal(tamperSeq), nil)
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
		},
	}

	// Outbound: a TTL=8 decoy SYN, then the real SYN untouched
	tamperTTL := NewTamperPrimitive("ttl", uint8(8))

	return NewStrategy(trigger, decoyThenReal(tamperTTL), nil)
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
		},
	}

	// Outbound: an RST decoy, then the real PSH-ACK untouched
	tamperFlags := NewTamperPrimitive("flags", uint8(TCPFlagRST))

	return NewStrategy(trigger, decoyThenReal(tamperFlags), nil)
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
		},
	}

	// Outbound: a zero-seq decoy, then the real SYN untouched
	tamperSeq := NewTamperPrimitive("seq", uint32(0))

	return NewStrategy(trigger, decoyThenReal(tamperSeq), nil)
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
		"china_gfw_1":      ChinaGFWStrategy1(),
		"china_gfw_2":      ChinaGFWStrategy2(),
		"china_gfw_3":      ChinaGFWStrategy3(),
		"iran_dpi_1":       IranDPIStrategy1(),
		"iran_dpi_2":       IranDPIStrategy2(),
		"russia_tspu_1":    RussiaTSPUStrategy1(),
		"russia_tspu_2":    RussiaTSPUStrategy2(),
		"russia_tspu_3":    RussiaTSPUStrategy3(),
		"turkey_dpi_1":     TurkeyDPIStrategy1(),
		"generic_fragment": GenericFragmentStrategy(),
		"generic_dup":      GenericDuplicateStrategy(),
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

// GetSuccessRate reports how often a strategy is expected to work.
//
// It always returns "unmeasured". Every strategy here used to carry a hardcoded
// percentage in its metadata - 85% for Russia TSPU 1, 90% for TSPU 2, 75% for
// China GFW 1 - with nothing behind any of them: no capture, no run against a
// live DPI, no cited source. They also described the packet-level behaviour as
// it was before decoyThenReal, which tampered the real packet along with the
// decoy and so could not have worked at all.
//
// The numbers are removed rather than corrected, because correcting them needs
// a measurement nobody has made. Callers that print this string now say so.
func (s *Strategy) GetSuccessRate() string {
	return "unmeasured"
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
