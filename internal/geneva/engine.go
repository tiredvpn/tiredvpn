package geneva

import (
	"errors"
	"fmt"
)

// Strategy represents a Geneva evasion strategy
// Format: "trigger:outbound-tree,inbound-tree"
// Example: "[TCP:flags:S]-drop-|" means drop SYN packets
type Strategy struct {
	Trigger      Trigger
	OutboundTree *ActionTree
	InboundTree  *ActionTree
}

// Trigger defines when to apply a strategy
type Trigger struct {
	Protocol string            // "TCP", "UDP"
	Field    string            // "flags", "seq", "payload"
	Value    interface{}       // Expected value
	Operator string            // "==", "!=", "contains"
	Metadata map[string]string // Additional metadata
}

// ActionTree represents a tree of Geneva actions
type ActionTree struct {
	Root     *ActionNode
	Branches []*ActionTree
}

// ActionNode represents a single action in the tree
type ActionNode struct {
	Primitive Primitive
	Next      *ActionNode
}

// NewStrategy creates a new Geneva strategy
func NewStrategy(trigger Trigger, outbound, inbound *ActionTree) *Strategy {
	return &Strategy{
		Trigger:      trigger,
		OutboundTree: outbound,
		InboundTree:  inbound,
	}
}

// Match checks if the trigger matches the packet
func (s *Strategy) Match(packet []byte) (bool, error) {
	if len(packet) < 20 {
		return false, errors.New("packet too short")
	}

	// Parse IP header
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	protocol := packet[9]

	// Check protocol match
	if s.Trigger.Protocol == "TCP" && protocol != 6 {
		return false, nil
	}
	if s.Trigger.Protocol == "UDP" && protocol != 17 {
		return false, nil
	}

	// Check field match
	switch s.Trigger.Field {
	case "flags":
		if protocol != 6 {
			return false, nil
		}
		flags, err := ParseTCPFlags(packet)
		if err != nil {
			return false, err
		}

		expectedFlags, ok := s.Trigger.Value.(uint8)
		if !ok {
			return false, errors.New("invalid trigger value for flags")
		}

		switch s.Trigger.Operator {
		case "==":
			return flags == expectedFlags, nil
		case "!=":
			return flags != expectedFlags, nil
		case "&":
			// Bitwise AND (check if flag is set)
			return (flags & expectedFlags) != 0, nil
		default:
			return flags == expectedFlags, nil
		}

	case "payload":
		// Check payload content
		if len(packet) < ipHeaderLen+20 {
			return false, nil
		}

		tcpStart := ipHeaderLen
		tcpHeaderLen := int((packet[tcpStart+12] >> 4) * 4)
		payloadStart := tcpStart + tcpHeaderLen

		if len(packet) <= payloadStart {
			return false, nil
		}

		payload := packet[payloadStart:]
		expectedBytes, ok := s.Trigger.Value.([]byte)
		if !ok {
			return false, errors.New("invalid trigger value for payload")
		}

		if s.Trigger.Operator == "contains" {
			return contains(payload, expectedBytes), nil
		}

		return false, nil

	default:
		return true, nil // No field check, always match
	}
}

// Apply applies the strategy to a packet
func (s *Strategy) Apply(packet []byte, isOutbound bool) ([][]byte, error) {
	match, err := s.Match(packet)
	if err != nil {
		return nil, err
	}

	if !match {
		// No match, return packet unmodified
		return [][]byte{packet}, nil
	}

	// Apply appropriate tree
	tree := s.OutboundTree
	if !isOutbound {
		tree = s.InboundTree
	}

	if tree == nil {
		return [][]byte{packet}, nil
	}

	return tree.Execute(packet)
}

// Execute executes the action tree on a packet
func (t *ActionTree) Execute(packet []byte) ([][]byte, error) {
	if t == nil || t.Root == nil {
		return [][]byte{packet}, nil
	}

	// Execute root node
	results, err := t.Root.Execute(packet)
	if err != nil {
		return nil, err
	}

	// If there are branches, execute them on each result
	if len(t.Branches) > 0 {
		var finalResults [][]byte
		for _, branch := range t.Branches {
			for _, pkt := range results {
				branchResults, err := branch.Execute(pkt)
				if err != nil {
					return nil, err
				}
				finalResults = append(finalResults, branchResults...)
			}
		}
		return finalResults, nil
	}

	return results, nil
}

// Execute executes the action node (and following nodes) on a packet
func (n *ActionNode) Execute(packet []byte) ([][]byte, error) {
	if n == nil {
		return [][]byte{packet}, nil
	}

	// Apply current primitive
	results, err := n.Primitive.Apply(packet)
	if err != nil {
		return nil, err
	}

	// If there's a next node, apply it to all results
	if n.Next != nil {
		var finalResults [][]byte
		for _, pkt := range results {
			nextResults, err := n.Next.Execute(pkt)
			if err != nil {
				return nil, err
			}
			finalResults = append(finalResults, nextResults...)
		}
		return finalResults, nil
	}

	return results, nil
}

// String returns a human-readable representation of the strategy
func (s *Strategy) String() string {
	triggerStr := fmt.Sprintf("[%s:%s:%v]", s.Trigger.Protocol, s.Trigger.Field, s.Trigger.Value)

	outboundStr := "send"
	if s.OutboundTree != nil {
		outboundStr = s.OutboundTree.String()
	}

	inboundStr := "send"
	if s.InboundTree != nil {
		inboundStr = s.InboundTree.String()
	}

	return triggerStr + "-" + outboundStr + "," + inboundStr
}

// String returns a string representation of the action tree
func (t *ActionTree) String() string {
	if t == nil || t.Root == nil {
		return "send"
	}

	result := t.Root.String()

	if len(t.Branches) > 0 {
		result += "|"
		for i, branch := range t.Branches {
			if i > 0 {
				result += ","
			}
			result += branch.String()
		}
	}

	return result
}

// String returns a string representation of the action node chain
func (n *ActionNode) String() string {
	if n == nil {
		return ""
	}

	result := n.Primitive.String()

	if n.Next != nil {
		result += "-" + n.Next.String()
	}

	return result
}

// NewActionTree creates a new action tree from a chain of primitives
func NewActionTree(primitives ...Primitive) *ActionTree {
	if len(primitives) == 0 {
		return nil
	}

	// Build chain
	var root, current *ActionNode
	for i, p := range primitives {
		node := &ActionNode{Primitive: p}
		if i == 0 {
			root = node
			current = node
		} else {
			current.Next = node
			current = node
		}
	}

	return &ActionTree{Root: root}
}

// AddBranch adds a branch to the action tree
func (t *ActionTree) AddBranch(branch *ActionTree) {
	if t.Branches == nil {
		t.Branches = []*ActionTree{}
	}
	t.Branches = append(t.Branches, branch)
}

// contains checks if haystack contains needle
func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}

	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
